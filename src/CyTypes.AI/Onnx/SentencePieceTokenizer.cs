using Microsoft.ML.Tokenizers;

namespace CyTypes.AI.Onnx;

/// <summary>
/// Word-aware wrapper around <see cref="Microsoft.ML.Tokenizers.SentencePieceTokenizer"/>
/// for the mDeBERTa-v3 vocabulary used by GLiNER. Tokenises a list of whitespace-split
/// words individually so that each subtoken can be mapped back to its source word
/// and to its character offsets in the original text.
/// </summary>
public sealed class GlinerSentencePieceTokenizer
{
    // Special token IDs from gliner_multi-v2.1 added_tokens.json + tokenizer_config.json
    public const int PadId = 0;
    public const int ClsId = 1;
    public const int SepId = 2;
    public const int UnkId = 3;
    public const int EntId = 250103;
    public const int EntSepId = 250104;

    private readonly SentencePieceTokenizer _spm;

    public GlinerSentencePieceTokenizer(string spmModelPath)
    {
        if (!File.Exists(spmModelPath))
            throw new FileNotFoundException($"spm.model not found at {spmModelPath}");
        using var fs = File.OpenRead(spmModelPath);
        _spm = SentencePieceTokenizer.Create(fs, addBeginningOfSentence: false, addEndOfSentence: false);
    }

    /// <summary>
    /// Returns the SentencePiece subtoken ids for a single word, no specials added.
    /// </summary>
    public List<int> EncodeWord(string word)
    {
        var ids = _spm.EncodeToIds(word, addBeginningOfSentence: false, addEndOfSentence: false);
        return ids.ToList();
    }

    /// <summary>
    /// Builds a full GLiNER input sequence from entity types + the original text.
    ///
    /// Layout:
    ///   [CLS] &lt;&lt;ENT&gt;&gt; ent1 &lt;&lt;ENT&gt;&gt; ent2 ... &lt;&lt;ENT&gt;&gt; entK &lt;&lt;SEP&gt;&gt; w1 w2 ... wN [SEP]
    ///
    /// `wordsMask` is 0 for special / prompt / continuation subtokens and 1, 2, 3, ...
    /// for the FIRST subtoken of each text word (1-indexed). `wordSpans[i]` gives
    /// the (charStart, charLen) of word i+1 in the original input.
    /// </summary>
    public GlinerEncoded EncodePrompt(string text, IReadOnlyList<string> entityTypes)
    {
        // Whitespace word split, recording original char offsets.
        var wordSpans = new List<(int charStart, int charLen, string word)>();
        int i = 0;
        while (i < text.Length)
        {
            while (i < text.Length && char.IsWhiteSpace(text[i])) i++;
            if (i >= text.Length) break;
            int start = i;
            while (i < text.Length && !char.IsWhiteSpace(text[i])) i++;
            wordSpans.Add((start, i - start, text.Substring(start, i - start)));
        }

        var inputIds = new List<long>();
        var wordsMask = new List<long>();

        // [CLS]
        inputIds.Add(ClsId);
        wordsMask.Add(0);

        // <<ENT>> ent_i for each entity type
        foreach (var ent in entityTypes)
        {
            inputIds.Add(EntId);
            wordsMask.Add(0);
            var entIds = _spm.EncodeToIds(ent, addBeginningOfSentence: false, addEndOfSentence: false);
            foreach (var id in entIds)
            {
                inputIds.Add(id);
                wordsMask.Add(0);
            }
        }

        // <<SEP>> separator before text
        inputIds.Add(EntSepId);
        wordsMask.Add(0);

        // Text words: each word's first subtoken gets a 1-indexed mask value
        int wordIndex = 1;
        foreach (var (_, _, w) in wordSpans)
        {
            var wIds = _spm.EncodeToIds(w, addBeginningOfSentence: false, addEndOfSentence: false);
            if (wIds.Count == 0)
            {
                inputIds.Add(UnkId);
                wordsMask.Add(wordIndex);
            }
            else
            {
                bool first = true;
                foreach (var id in wIds)
                {
                    inputIds.Add(id);
                    wordsMask.Add(first ? wordIndex : 0);
                    first = false;
                }
            }
            wordIndex++;
        }

        // [SEP]
        inputIds.Add(SepId);
        wordsMask.Add(0);

        // attention mask = 1 for all real tokens (no padding here, padding done by caller if batched)
        var attentionMask = new long[inputIds.Count];
        for (int t = 0; t < attentionMask.Length; t++) attentionMask[t] = 1;

        return new GlinerEncoded
        {
            InputIds = inputIds.ToArray(),
            AttentionMask = attentionMask,
            WordsMask = wordsMask.ToArray(),
            NumWords = wordSpans.Count,
            WordSpans = wordSpans.Select(w => (w.charStart, w.charLen)).ToArray(),
            Words = wordSpans.Select(w => w.word).ToArray(),
        };
    }
}

public sealed class GlinerEncoded
{
    public long[] InputIds { get; init; } = Array.Empty<long>();
    public long[] AttentionMask { get; init; } = Array.Empty<long>();
    public long[] WordsMask { get; init; } = Array.Empty<long>();
    public int NumWords { get; init; }
    public (int charStart, int charLen)[] WordSpans { get; init; } = Array.Empty<(int, int)>();
    public string[] Words { get; init; } = Array.Empty<string>();
}
