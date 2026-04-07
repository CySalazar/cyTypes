using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;

namespace CyTypes.AI.Onnx;

/// <summary>
/// Wraps the GLiNER multi v2.1 ONNX model (mDeBERTa-v3-base, span-mode markerV0).
///
/// Inputs (all int64 unless noted):
///   - input_ids        [B, T]
///   - attention_mask   [B, T]
///   - words_mask       [B, T]
///   - text_lengths     [B, 1]
///   - span_idx         [B, S, 2]
///   - span_mask        [B, S]   (bool)
///
/// Output:
///   - logits           [B, L, K, C]
///       L = num text words
///       K = max span width (12)
///       C = num entity types passed in the prompt
/// </summary>
public sealed class GlinerOnnxModel : IDisposable
{
    public const int MaxWidth = 12;          // from gliner_config.json
    public const int MaxSeqLen = 384;        // from gliner_config.json

    private readonly InferenceSession _session;
    private readonly GlinerSentencePieceTokenizer _tokenizer;

    public GlinerOnnxModel(string modelPath, string spmModelPath)
    {
        var so = new SessionOptions
        {
            GraphOptimizationLevel = GraphOptimizationLevel.ORT_ENABLE_ALL,
            IntraOpNumThreads = Math.Max(1, Environment.ProcessorCount / 2),
            LogSeverityLevel = OrtLoggingLevel.ORT_LOGGING_LEVEL_ERROR,
        };
        so.AppendExecutionProvider_CPU(0);
        _session = new InferenceSession(modelPath, so);
        _tokenizer = new GlinerSentencePieceTokenizer(spmModelPath);
    }

    public sealed record EntitySpan(int CharStart, int CharLength, string Label, float Score, string Text);

    /// <summary>
    /// Run GLiNER on a piece of text. Returns all spans whose score is &gt;= threshold,
    /// after greedy NMS to remove overlaps (flat NER).
    /// </summary>
    public List<EntitySpan> Run(string text, IReadOnlyList<string> entityTypes, float threshold = 0.5f)
    {
        if (string.IsNullOrEmpty(text) || entityTypes.Count == 0) return new();

        var enc = _tokenizer.EncodePrompt(text, entityTypes);
        if (enc.NumWords == 0) return new();

        // Truncate to MaxSeqLen if necessary (drop trailing tokens; cheap, very rare for short prompts).
        int t = Math.Min(enc.InputIds.Length, MaxSeqLen);
        var inputIds = new long[t];
        var attentionMask = new long[t];
        var wordsMask = new long[t];
        Array.Copy(enc.InputIds, inputIds, t);
        Array.Copy(enc.AttentionMask, attentionMask, t);
        Array.Copy(enc.WordsMask, wordsMask, t);

        // Effective number of words after truncation
        int numWords = 0;
        for (int i = 0; i < t; i++)
            if (wordsMask[i] > numWords) numWords = (int)wordsMask[i];
        if (numWords == 0) return new();

        // Build candidate spans: all (start, width) with start+width < numWords
        var spanIdxList = new List<long>(numWords * MaxWidth * 2);
        for (int s = 0; s < numWords; s++)
            for (int w = 0; w < MaxWidth; w++)
            {
                spanIdxList.Add(s);
                spanIdxList.Add(s + w);
            }
        int numSpans = numWords * MaxWidth;
        var spanMask = new bool[numSpans];
        int idx = 0;
        for (int s = 0; s < numWords; s++)
            for (int w = 0; w < MaxWidth; w++, idx++)
                spanMask[idx] = (s + w) < numWords;

        // Tensors (batch=1)
        var inputs = new List<NamedOnnxValue>
        {
            NamedOnnxValue.CreateFromTensor("input_ids",      new DenseTensor<long>(inputIds, new[] { 1, t })),
            NamedOnnxValue.CreateFromTensor("attention_mask", new DenseTensor<long>(attentionMask, new[] { 1, t })),
            NamedOnnxValue.CreateFromTensor("words_mask",     new DenseTensor<long>(wordsMask, new[] { 1, t })),
            NamedOnnxValue.CreateFromTensor("text_lengths",   new DenseTensor<long>(new long[] { numWords }, new[] { 1, 1 })),
            NamedOnnxValue.CreateFromTensor("span_idx",       new DenseTensor<long>(spanIdxList.ToArray(), new[] { 1, numSpans, 2 })),
            NamedOnnxValue.CreateFromTensor("span_mask",      new DenseTensor<bool>(spanMask, new[] { 1, numSpans })),
        };

        using var results = _session.Run(inputs);
        var logits = results.First(r => r.Name == "logits").AsTensor<float>();
        // Shape: [1, L, K, C]
        var dims = logits.Dimensions.ToArray();
        int L = dims[1];
        int K = dims[2];
        int C = dims[3];


        // Decode: sigmoid + threshold + valid span check
        var candidates = new List<(int s, int w, int c, float score)>();
        for (int s = 0; s < L; s++)
            for (int w = 0; w < K; w++)
            {
                if (s + w + 1 > L) break; // span exceeds words
                for (int c = 0; c < C; c++)
                {
                    float lg = logits[0, s, w, c];
                    float p = Sigmoid(lg);
                    if (p >= threshold)
                        candidates.Add((s, w, c, p));
                }
            }

        // Greedy NMS (flat NER): sort desc by score, keep non-overlapping
        candidates.Sort((a, b) => b.score.CompareTo(a.score));
        var kept = new List<(int s, int w, int c, float score)>();
        foreach (var cand in candidates)
        {
            int sStart = cand.s, sEnd = cand.s + cand.w;
            bool overlap = false;
            foreach (var k in kept)
            {
                int kStart = k.s, kEnd = k.s + k.w;
                if (sStart <= kEnd && kStart <= sEnd) { overlap = true; break; }
            }
            if (!overlap) kept.Add(cand);
        }

        // Map word-level (s, s+w) → char-level using WordSpans
        var output = new List<EntitySpan>();
        foreach (var (s, w, c, score) in kept)
        {
            if (s >= enc.WordSpans.Length || s + w >= enc.WordSpans.Length) continue;
            var firstWord = enc.WordSpans[s];
            var lastWord = enc.WordSpans[s + w];
            int charStart = firstWord.charStart;
            int charEnd = lastWord.charStart + lastWord.charLen;
            // Strip trailing punctuation (. , ; : ! ? ) ] ") so spans like
            // "chemotherapy." normalise to "chemotherapy" and dedupe with the
            // heuristic finder.
            while (charEnd > charStart && IsTrailingPunct(text[charEnd - 1])) charEnd--;
            int charLen = charEnd - charStart;
            if (charLen <= 0) continue;
            string label = entityTypes[c];
            string spanText = text.Substring(charStart, charLen);
            output.Add(new EntitySpan(charStart, charLen, label, score, spanText));
        }
        // Sort by start position
        output.Sort((a, b) => a.CharStart.CompareTo(b.CharStart));
        return output;
    }

    private static float Sigmoid(float x) => 1f / (1f + (float)Math.Exp(-x));
    private static bool IsTrailingPunct(char c) => c is '.' or ',' or ';' or ':' or '!' or '?' or ')' or ']' or '"' or '\'' or '»';

    public void Dispose() => _session.Dispose();
}
