
#-------------------------------------------------------- EnvironmentVerifier  ------------------------------------------
function Test-ValidOperatingSystemArch
{
	try
	{
		$ArchCode = (Get-CimInstance -Class Win32_Processor).Architecture
	}
	catch
	{
		$ArchCode = -1
	}

	# 0 - x86,  9 - x64
	return $ArchCode -eq 0 -Or $ArchCode -eq 9
}

#--------------------------------------------------- EnvironmentVerifier End  -------------------------------------------
if (!(Test-ValidOperatingSystemArch)) {
	Write-Host 'Script cannot run on non x86 or x64 systems'
	exit
}

$Error.Clear()
$ErrorActionPreference = 'Stop'

function Import-CSharpLibrary {
    [CmdletBinding()]
    param (
        # Path to the .cs file.
        [Parameter(Mandatory=$true)]
        [string] $Path,

        # Should ignore compilation warnings.
        [Parameter()]
        [switch] $IgnoreWarnings
    )
    $code = Get-Content -LiteralPath $Path -Raw
    Add-Type -TypeDefinition $code -Language CSharp -IgnoreWarnings:$IgnoreWarnings
}


$LZMA_CS_2951093068 = @"
using System;
using System.IO;

namespace SevenZip.Compression.RangeCoder
{
	class Encoder
	{
		public const uint kTopValue = (1 << 24);

		System.IO.Stream Stream;

		public UInt64 Low;
		public uint Range;
		uint _cacheSize;
		byte _cache;

		long StartPosition;

		public void SetStream(System.IO.Stream stream)
		{
			Stream = stream;
		}

		public void ReleaseStream()
		{
			Stream = null;
		}

		public void Init()
		{
			StartPosition = Stream.Position;

			Low = 0;
			Range = 0xFFFFFFFF;
			_cacheSize = 1;
			_cache = 0;
		}

		public void FlushData()
		{
			for (int i = 0; i < 5; i++)
				ShiftLow();
		}

		public void FlushStream()
		{
			Stream.Flush();
		}

		public void CloseStream()
		{
			Stream.Close();
		}

		public void Encode(uint start, uint size, uint total)
		{
			Low += start * (Range /= total);
			Range *= size;
			while (Range < kTopValue)
			{
				Range <<= 8;
				ShiftLow();
			}
		}

		public void ShiftLow()
		{
			if ((uint)Low < (uint)0xFF000000 || (uint)(Low >> 32) == 1)
			{
				byte temp = _cache;
				do
				{
					Stream.WriteByte((byte)(temp + (Low >> 32)));
					temp = 0xFF;
				}
				while (--_cacheSize != 0);
				_cache = (byte)(((uint)Low) >> 24);
			}
			_cacheSize++;
			Low = ((uint)Low) << 8;
		}

		public void EncodeDirectBits(uint v, int numTotalBits)
		{
			for (int i = numTotalBits - 1; i >= 0; i--)
			{
				Range >>= 1;
				if (((v >> i) & 1) == 1)
					Low += Range;
				if (Range < kTopValue)
				{
					Range <<= 8;
					ShiftLow();
				}
			}
		}

		public void EncodeBit(uint size0, int numTotalBits, uint symbol)
		{
			uint newBound = (Range >> numTotalBits) * size0;
			if (symbol == 0)
				Range = newBound;
			else
			{
				Low += newBound;
				Range -= newBound;
			}
			while (Range < kTopValue)
			{
				Range <<= 8;
				ShiftLow();
			}
		}

		public long GetProcessedSizeAdd()
		{
			return _cacheSize +
				Stream.Position - StartPosition + 4;
			// (long)Stream.GetProcessedSize();
		}
	}

	class Decoder
	{
		public const uint kTopValue = (1 << 24);
		public uint Range;
		public uint Code;
		// public Buffer.InBuffer Stream = new Buffer.InBuffer(1 << 16);
		public System.IO.Stream Stream;

		public void Init(System.IO.Stream stream)
		{
			// Stream.Init(stream);
			Stream = stream;

			Code = 0;
			Range = 0xFFFFFFFF;
			for (int i = 0; i < 5; i++)
				Code = (Code << 8) | (byte)Stream.ReadByte();
		}

		public void ReleaseStream()
		{
			// Stream.ReleaseStream();
			Stream = null;
		}

		public void CloseStream()
		{
			Stream.Close();
		}

		public void Normalize()
		{
			while (Range < kTopValue)
			{
				Code = (Code << 8) | (byte)Stream.ReadByte();
				Range <<= 8;
			}
		}

		public void Normalize2()
		{
			if (Range < kTopValue)
			{
				Code = (Code << 8) | (byte)Stream.ReadByte();
				Range <<= 8;
			}
		}

		public uint GetThreshold(uint total)
		{
			return Code / (Range /= total);
		}

		public void Decode(uint start, uint size, uint total)
		{
			Code -= start * Range;
			Range *= size;
			Normalize();
		}

		public uint DecodeDirectBits(int numTotalBits)
		{
			uint range = Range;
			uint code = Code;
			uint result = 0;
			for (int i = numTotalBits; i > 0; i--)
			{
				range >>= 1;
				/*
				result <<= 1;
				if (code >= range)
				{
					code -= range;
					result |= 1;
				}
				*/
				uint t = (code - range) >> 31;
				code -= range & (t - 1);
				result = (result << 1) | (1 - t);

				if (range < kTopValue)
				{
					code = (code << 8) | (byte)Stream.ReadByte();
					range <<= 8;
				}
			}
			Range = range;
			Code = code;
			return result;
		}

		public uint DecodeBit(uint size0, int numTotalBits)
		{
			uint newBound = (Range >> numTotalBits) * size0;
			uint symbol;
			if (Code < newBound)
			{
				symbol = 0;
				Range = newBound;
			}
			else
			{
				symbol = 1;
				Code -= newBound;
				Range -= newBound;
			}
			Normalize();
			return symbol;
		}

		// ulong GetProcessedSize() {return Stream.GetProcessedSize(); }
	}
}

namespace SevenZip
{
	/// <summary>
	/// The exception that is thrown when an error in input stream occurs during decoding.
	/// </summary>
	class DataErrorException : ApplicationException
	{
		public DataErrorException() : base("Data Error") { }
	}

	/// <summary>
	/// The exception that is thrown when the value of an argument is outside the allowable range.
	/// </summary>
	class InvalidParamException : ApplicationException
	{
		public InvalidParamException() : base("Invalid Parameter") { }
	}

	public interface ICodeProgress
	{
		/// <summary>
		/// Callback progress.
		/// </summary>
		/// <param name="inSize">
		/// input size. -1 if unknown.
		/// </param>
		/// <param name="outSize">
		/// output size. -1 if unknown.
		/// </param>
		void SetProgress(Int64 inSize, Int64 outSize);
	};

	public interface ICoder
	{
		/// <summary>
		/// Codes streams.
		/// </summary>
		/// <param name="inStream">
		/// input Stream.
		/// </param>
		/// <param name="outStream">
		/// output Stream.
		/// </param>
		/// <param name="inSize">
		/// input Size. -1 if unknown.
		/// </param>
		/// <param name="outSize">
		/// output Size. -1 if unknown.
		/// </param>
		/// <param name="progress">
		/// callback progress reference.
		/// </param>
		/// <exception cref="SevenZip.DataErrorException">
		/// if input stream is not valid
		/// </exception>
		void Code(System.IO.Stream inStream, System.IO.Stream outStream,
			Int64 inSize, Int64 outSize, ICodeProgress progress);
	};

	/*
	public interface ICoder2
	{
		 void Code(ISequentialInStream []inStreams,
				const UInt64 []inSizes,
				ISequentialOutStream []outStreams,
				UInt64 []outSizes,
				ICodeProgress progress);
	};
  */

	/// <summary>
	/// Provides the fields that represent properties idenitifiers for compressing.
	/// </summary>
	public enum CoderPropID
	{
		/// <summary>
		/// Specifies default property.
		/// </summary>
		DefaultProp = 0,
		/// <summary>
		/// Specifies size of dictionary.
		/// </summary>
		DictionarySize,
		/// <summary>
		/// Specifies size of memory for PPM*.
		/// </summary>
		UsedMemorySize,
		/// <summary>
		/// Specifies order for PPM methods.
		/// </summary>
		Order,
		/// <summary>
		/// Specifies Block Size.
		/// </summary>
		BlockSize,
		/// <summary>
		/// Specifies number of postion state bits for LZMA (0 <= x <= 4).
		/// </summary>
		PosStateBits,
		/// <summary>
		/// Specifies number of literal context bits for LZMA (0 <= x <= 8).
		/// </summary>
		LitContextBits,
		/// <summary>
		/// Specifies number of literal position bits for LZMA (0 <= x <= 4).
		/// </summary>
		LitPosBits,
		/// <summary>
		/// Specifies number of fast bytes for LZ*.
		/// </summary>
		NumFastBytes,
		/// <summary>
		/// Specifies match finder. LZMA: "BT2", "BT4" or "BT4B".
		/// </summary>
		MatchFinder,
		/// <summary>
		/// Specifies the number of match finder cyckes.
		/// </summary>
		MatchFinderCycles,
		/// <summary>
		/// Specifies number of passes.
		/// </summary>
		NumPasses,
		/// <summary>
		/// Specifies number of algorithm.
		/// </summary>
		Algorithm,
		/// <summary>
		/// Specifies the number of threads.
		/// </summary>
		NumThreads,
		/// <summary>
		/// Specifies mode with end marker.
		/// </summary>
		EndMarker
	};


	public interface ISetCoderProperties
	{
		void SetCoderProperties(CoderPropID[] propIDs, object[] properties);
	};

	public interface IWriteCoderProperties
	{
		void WriteCoderProperties(System.IO.Stream outStream);
	}

	public interface ISetDecoderProperties
	{
		void SetDecoderProperties(byte[] properties);
	}
}

namespace SevenZip.Compression.RangeCoder
{
	struct BitEncoder
	{
		public const int kNumBitModelTotalBits = 11;
		public const uint kBitModelTotal = (1 << kNumBitModelTotalBits);
		const int kNumMoveBits = 5;
		const int kNumMoveReducingBits = 2;
		public const int kNumBitPriceShiftBits = 6;

		uint Prob;

		public void Init() { Prob = kBitModelTotal >> 1; }

		public void UpdateModel(uint symbol)
		{
			if (symbol == 0)
				Prob += (kBitModelTotal - Prob) >> kNumMoveBits;
			else
				Prob -= (Prob) >> kNumMoveBits;
		}

		public void Encode(Encoder encoder, uint symbol)
		{
			// encoder.EncodeBit(Prob, kNumBitModelTotalBits, symbol);
			// UpdateModel(symbol);
			uint newBound = (encoder.Range >> kNumBitModelTotalBits) * Prob;
			if (symbol == 0)
			{
				encoder.Range = newBound;
				Prob += (kBitModelTotal - Prob) >> kNumMoveBits;
			}
			else
			{
				encoder.Low += newBound;
				encoder.Range -= newBound;
				Prob -= (Prob) >> kNumMoveBits;
			}
			if (encoder.Range < Encoder.kTopValue)
			{
				encoder.Range <<= 8;
				encoder.ShiftLow();
			}
		}

		private static UInt32[] ProbPrices = new UInt32[kBitModelTotal >> kNumMoveReducingBits];

		static BitEncoder()
		{
			const int kNumBits = (kNumBitModelTotalBits - kNumMoveReducingBits);
			for (int i = kNumBits - 1; i >= 0; i--)
			{
				UInt32 start = (UInt32)1 << (kNumBits - i - 1);
				UInt32 end = (UInt32)1 << (kNumBits - i);
				for (UInt32 j = start; j < end; j++)
					ProbPrices[j] = ((UInt32)i << kNumBitPriceShiftBits) +
						(((end - j) << kNumBitPriceShiftBits) >> (kNumBits - i - 1));
			}
		}

		public uint GetPrice(uint symbol)
		{
			return ProbPrices[(((Prob - symbol) ^ ((-(int)symbol))) & (kBitModelTotal - 1)) >> kNumMoveReducingBits];
		}
		public uint GetPrice0() { return ProbPrices[Prob >> kNumMoveReducingBits]; }
		public uint GetPrice1() { return ProbPrices[(kBitModelTotal - Prob) >> kNumMoveReducingBits]; }
	}

	struct BitDecoder
	{
		public const int kNumBitModelTotalBits = 11;
		public const uint kBitModelTotal = (1 << kNumBitModelTotalBits);
		const int kNumMoveBits = 5;

		uint Prob;

		public void UpdateModel(int numMoveBits, uint symbol)
		{
			if (symbol == 0)
				Prob += (kBitModelTotal - Prob) >> numMoveBits;
			else
				Prob -= (Prob) >> numMoveBits;
		}

		public void Init() { Prob = kBitModelTotal >> 1; }

		public uint Decode(RangeCoder.Decoder rangeDecoder)
		{
			uint newBound = (uint)(rangeDecoder.Range >> kNumBitModelTotalBits) * (uint)Prob;
			if (rangeDecoder.Code < newBound)
			{
				rangeDecoder.Range = newBound;
				Prob += (kBitModelTotal - Prob) >> kNumMoveBits;
				if (rangeDecoder.Range < Decoder.kTopValue)
				{
					rangeDecoder.Code = (rangeDecoder.Code << 8) | (byte)rangeDecoder.Stream.ReadByte();
					rangeDecoder.Range <<= 8;
				}
				return 0;
			}
			else
			{
				rangeDecoder.Range -= newBound;
				rangeDecoder.Code -= newBound;
				Prob -= (Prob) >> kNumMoveBits;
				if (rangeDecoder.Range < Decoder.kTopValue)
				{
					rangeDecoder.Code = (rangeDecoder.Code << 8) | (byte)rangeDecoder.Stream.ReadByte();
					rangeDecoder.Range <<= 8;
				}
				return 1;
			}
		}
	}
}

namespace SevenZip.Compression.LZ
{
	public class OutWindow
	{
		byte[] _buffer = null;
		uint _pos;
		uint _windowSize = 0;
		uint _streamPos;
		System.IO.Stream _stream;

		public uint TrainSize = 0;

		public void Create(uint windowSize)
		{
			if (_windowSize != windowSize)
			{
				// System.GC.Collect();
				_buffer = new byte[windowSize];
			}
			_windowSize = windowSize;
			_pos = 0;
			_streamPos = 0;
		}

		public void Init(System.IO.Stream stream, bool solid)
		{
			ReleaseStream();
			_stream = stream;
			if (!solid)
			{
				_streamPos = 0;
				_pos = 0;
				TrainSize = 0;
			}
		}

		public bool Train(System.IO.Stream stream)
		{
			long len = stream.Length;
			uint size = (len < _windowSize) ? (uint)len : _windowSize;
			TrainSize = size;
			stream.Position = len - size;
			_streamPos = _pos = 0;
			while (size > 0)
			{
				uint curSize = _windowSize - _pos;
				if (size < curSize)
					curSize = size;
				int numReadBytes = stream.Read(_buffer, (int)_pos, (int)curSize);
				if (numReadBytes == 0)
					return false;
				size -= (uint)numReadBytes;
				_pos += (uint)numReadBytes;
				_streamPos += (uint)numReadBytes;
				if (_pos == _windowSize)
					_streamPos = _pos = 0;
			}
			return true;
		}

		public void ReleaseStream()
		{
			Flush();
			_stream = null;
		}

		public void Flush()
		{
			uint size = _pos - _streamPos;
			if (size == 0)
				return;
			_stream.Write(_buffer, (int)_streamPos, (int)size);
			if (_pos >= _windowSize)
				_pos = 0;
			_streamPos = _pos;
		}

		public void CopyBlock(uint distance, uint len)
		{
			uint pos = _pos - distance - 1;
			if (pos >= _windowSize)
				pos += _windowSize;
			for (; len > 0; len--)
			{
				if (pos >= _windowSize)
					pos = 0;
				_buffer[_pos++] = _buffer[pos++];
				if (_pos >= _windowSize)
					Flush();
			}
		}

		public void PutByte(byte b)
		{
			_buffer[_pos++] = b;
			if (_pos >= _windowSize)
				Flush();
		}

		public byte GetByte(uint distance)
		{
			uint pos = _pos - distance - 1;
			if (pos >= _windowSize)
				pos += _windowSize;
			return _buffer[pos];
		}
	}
}
namespace SevenZip.Compression.RangeCoder
{
	struct BitTreeDecoder
	{
		BitDecoder[] Models;
		int NumBitLevels;

		public BitTreeDecoder(int numBitLevels)
		{
			NumBitLevels = numBitLevels;
			Models = new BitDecoder[1 << numBitLevels];
		}

		public void Init()
		{
			for (uint i = 1; i < (1 << NumBitLevels); i++)
				Models[i].Init();
		}

		public uint Decode(RangeCoder.Decoder rangeDecoder)
		{
			uint m = 1;
			for (int bitIndex = NumBitLevels; bitIndex > 0; bitIndex--)
				m = (m << 1) + Models[m].Decode(rangeDecoder);
			return m - ((uint)1 << NumBitLevels);
		}

		public uint ReverseDecode(RangeCoder.Decoder rangeDecoder)
		{
			uint m = 1;
			uint symbol = 0;
			for (int bitIndex = 0; bitIndex < NumBitLevels; bitIndex++)
			{
				uint bit = Models[m].Decode(rangeDecoder);
				m <<= 1;
				m += bit;
				symbol |= (bit << bitIndex);
			}
			return symbol;
		}

		public static uint ReverseDecode(BitDecoder[] Models, UInt32 startIndex,
			RangeCoder.Decoder rangeDecoder, int NumBitLevels)
		{
			uint m = 1;
			uint symbol = 0;
			for (int bitIndex = 0; bitIndex < NumBitLevels; bitIndex++)
			{
				uint bit = Models[startIndex + m].Decode(rangeDecoder);
				m <<= 1;
				m += bit;
				symbol |= (bit << bitIndex);
			}
			return symbol;
		}
	}
}

namespace SevenZip.Compression.RangeCoder
{
	struct BitTreeEncoder
	{
		BitEncoder[] Models;
		int NumBitLevels;

		public BitTreeEncoder(int numBitLevels)
		{
			NumBitLevels = numBitLevels;
			Models = new BitEncoder[1 << numBitLevels];
		}

		public void Init()
		{
			for (uint i = 1; i < (1 << NumBitLevels); i++)
				Models[i].Init();
		}

		public void Encode(Encoder rangeEncoder, UInt32 symbol)
		{
			UInt32 m = 1;
			for (int bitIndex = NumBitLevels; bitIndex > 0;)
			{
				bitIndex--;
				UInt32 bit = (symbol >> bitIndex) & 1;
				Models[m].Encode(rangeEncoder, bit);
				m = (m << 1) | bit;
			}
		}

		public void ReverseEncode(Encoder rangeEncoder, UInt32 symbol)
		{
			UInt32 m = 1;
			for (UInt32 i = 0; i < NumBitLevels; i++)
			{
				UInt32 bit = symbol & 1;
				Models[m].Encode(rangeEncoder, bit);
				m = (m << 1) | bit;
				symbol >>= 1;
			}
		}

		public UInt32 GetPrice(UInt32 symbol)
		{
			UInt32 price = 0;
			UInt32 m = 1;
			for (int bitIndex = NumBitLevels; bitIndex > 0;)
			{
				bitIndex--;
				UInt32 bit = (symbol >> bitIndex) & 1;
				price += Models[m].GetPrice(bit);
				m = (m << 1) + bit;
			}
			return price;
		}

		public UInt32 ReverseGetPrice(UInt32 symbol)
		{
			UInt32 price = 0;
			UInt32 m = 1;
			for (int i = NumBitLevels; i > 0; i--)
			{
				UInt32 bit = symbol & 1;
				symbol >>= 1;
				price += Models[m].GetPrice(bit);
				m = (m << 1) | bit;
			}
			return price;
		}

		public static UInt32 ReverseGetPrice(BitEncoder[] Models, UInt32 startIndex,
			int NumBitLevels, UInt32 symbol)
		{
			UInt32 price = 0;
			UInt32 m = 1;
			for (int i = NumBitLevels; i > 0; i--)
			{
				UInt32 bit = symbol & 1;
				symbol >>= 1;
				price += Models[startIndex + m].GetPrice(bit);
				m = (m << 1) | bit;
			}
			return price;
		}

		public static void ReverseEncode(BitEncoder[] Models, UInt32 startIndex,
			Encoder rangeEncoder, int NumBitLevels, UInt32 symbol)
		{
			UInt32 m = 1;
			for (int i = 0; i < NumBitLevels; i++)
			{
				UInt32 bit = symbol & 1;
				Models[startIndex + m].Encode(rangeEncoder, bit);
				m = (m << 1) | bit;
				symbol >>= 1;
			}
		}
	}
}

namespace SevenZip.Compression.LZMA
{
	internal abstract class Base
	{
		public const uint kNumRepDistances = 4;
		public const uint kNumStates = 12;

		// static byte []kLiteralNextStates  = {0, 0, 0, 0, 1, 2, 3, 4,  5,  6,   4, 5};
		// static byte []kMatchNextStates    = {7, 7, 7, 7, 7, 7, 7, 10, 10, 10, 10, 10};
		// static byte []kRepNextStates      = {8, 8, 8, 8, 8, 8, 8, 11, 11, 11, 11, 11};
		// static byte []kShortRepNextStates = {9, 9, 9, 9, 9, 9, 9, 11, 11, 11, 11, 11};

		public struct State
		{
			public uint Index;
			public void Init() { Index = 0; }
			public void UpdateChar()
			{
				if (Index < 4) Index = 0;
				else if (Index < 10) Index -= 3;
				else Index -= 6;
			}
			public void UpdateMatch() { Index = (uint)(Index < 7 ? 7 : 10); }
			public void UpdateRep() { Index = (uint)(Index < 7 ? 8 : 11); }
			public void UpdateShortRep() { Index = (uint)(Index < 7 ? 9 : 11); }
			public bool IsCharState() { return Index < 7; }
		}

		public const int kNumPosSlotBits = 6;
		public const int kDicLogSizeMin = 0;
		// public const int kDicLogSizeMax = 30;
		// public const uint kDistTableSizeMax = kDicLogSizeMax * 2;

		public const int kNumLenToPosStatesBits = 2; // it's for speed optimization
		public const uint kNumLenToPosStates = 1 << kNumLenToPosStatesBits;

		public const uint kMatchMinLen = 2;

		public static uint GetLenToPosState(uint len)
		{
			len -= kMatchMinLen;
			if (len < kNumLenToPosStates)
				return len;
			return (uint)(kNumLenToPosStates - 1);
		}

		public const int kNumAlignBits = 4;
		public const uint kAlignTableSize = 1 << kNumAlignBits;
		public const uint kAlignMask = (kAlignTableSize - 1);

		public const uint kStartPosModelIndex = 4;
		public const uint kEndPosModelIndex = 14;
		public const uint kNumPosModels = kEndPosModelIndex - kStartPosModelIndex;

		public const uint kNumFullDistances = 1 << ((int)kEndPosModelIndex / 2);

		public const uint kNumLitPosStatesBitsEncodingMax = 4;
		public const uint kNumLitContextBitsMax = 8;

		public const int kNumPosStatesBitsMax = 4;
		public const uint kNumPosStatesMax = (1 << kNumPosStatesBitsMax);
		public const int kNumPosStatesBitsEncodingMax = 4;
		public const uint kNumPosStatesEncodingMax = (1 << kNumPosStatesBitsEncodingMax);

		public const int kNumLowLenBits = 3;
		public const int kNumMidLenBits = 3;
		public const int kNumHighLenBits = 8;
		public const uint kNumLowLenSymbols = 1 << kNumLowLenBits;
		public const uint kNumMidLenSymbols = 1 << kNumMidLenBits;
		public const uint kNumLenSymbols = kNumLowLenSymbols + kNumMidLenSymbols +
				(1 << kNumHighLenBits);
		public const uint kMatchMaxLen = kMatchMinLen + kNumLenSymbols - 1;
	}
}

namespace SevenZip.Compression.LZMA
{
	using RangeCoder;

	public class Decoder : ICoder, ISetDecoderProperties // ,System.IO.Stream
	{
		class LenDecoder
		{
			BitDecoder m_Choice = new BitDecoder();
			BitDecoder m_Choice2 = new BitDecoder();
			BitTreeDecoder[] m_LowCoder = new BitTreeDecoder[Base.kNumPosStatesMax];
			BitTreeDecoder[] m_MidCoder = new BitTreeDecoder[Base.kNumPosStatesMax];
			BitTreeDecoder m_HighCoder = new BitTreeDecoder(Base.kNumHighLenBits);
			uint m_NumPosStates = 0;

			public void Create(uint numPosStates)
			{
				for (uint posState = m_NumPosStates; posState < numPosStates; posState++)
				{
					m_LowCoder[posState] = new BitTreeDecoder(Base.kNumLowLenBits);
					m_MidCoder[posState] = new BitTreeDecoder(Base.kNumMidLenBits);
				}
				m_NumPosStates = numPosStates;
			}

			public void Init()
			{
				m_Choice.Init();
				for (uint posState = 0; posState < m_NumPosStates; posState++)
				{
					m_LowCoder[posState].Init();
					m_MidCoder[posState].Init();
				}
				m_Choice2.Init();
				m_HighCoder.Init();
			}

			public uint Decode(RangeCoder.Decoder rangeDecoder, uint posState)
			{
				if (m_Choice.Decode(rangeDecoder) == 0)
					return m_LowCoder[posState].Decode(rangeDecoder);
				else
				{
					uint symbol = Base.kNumLowLenSymbols;
					if (m_Choice2.Decode(rangeDecoder) == 0)
						symbol += m_MidCoder[posState].Decode(rangeDecoder);
					else
					{
						symbol += Base.kNumMidLenSymbols;
						symbol += m_HighCoder.Decode(rangeDecoder);
					}
					return symbol;
				}
			}
		}

		class LiteralDecoder
		{
			struct Decoder2
			{
				BitDecoder[] m_Decoders;
				public void Create() { m_Decoders = new BitDecoder[0x300]; }
				public void Init() { for (int i = 0; i < 0x300; i++) m_Decoders[i].Init(); }

				public byte DecodeNormal(RangeCoder.Decoder rangeDecoder)
				{
					uint symbol = 1;
					do
						symbol = (symbol << 1) | m_Decoders[symbol].Decode(rangeDecoder);
					while (symbol < 0x100);
					return (byte)symbol;
				}

				public byte DecodeWithMatchByte(RangeCoder.Decoder rangeDecoder, byte matchByte)
				{
					uint symbol = 1;
					do
					{
						uint matchBit = (uint)(matchByte >> 7) & 1;
						matchByte <<= 1;
						uint bit = m_Decoders[((1 + matchBit) << 8) + symbol].Decode(rangeDecoder);
						symbol = (symbol << 1) | bit;
						if (matchBit != bit)
						{
							while (symbol < 0x100)
								symbol = (symbol << 1) | m_Decoders[symbol].Decode(rangeDecoder);
							break;
						}
					}
					while (symbol < 0x100);
					return (byte)symbol;
				}
			}

			Decoder2[] m_Coders;
			int m_NumPrevBits;
			int m_NumPosBits;
			uint m_PosMask;

			public void Create(int numPosBits, int numPrevBits)
			{
				if (m_Coders != null && m_NumPrevBits == numPrevBits &&
					m_NumPosBits == numPosBits)
					return;
				m_NumPosBits = numPosBits;
				m_PosMask = ((uint)1 << numPosBits) - 1;
				m_NumPrevBits = numPrevBits;
				uint numStates = (uint)1 << (m_NumPrevBits + m_NumPosBits);
				m_Coders = new Decoder2[numStates];
				for (uint i = 0; i < numStates; i++)
					m_Coders[i].Create();
			}

			public void Init()
			{
				uint numStates = (uint)1 << (m_NumPrevBits + m_NumPosBits);
				for (uint i = 0; i < numStates; i++)
					m_Coders[i].Init();
			}

			uint GetState(uint pos, byte prevByte)
			{ return ((pos & m_PosMask) << m_NumPrevBits) + (uint)(prevByte >> (8 - m_NumPrevBits)); }

			public byte DecodeNormal(RangeCoder.Decoder rangeDecoder, uint pos, byte prevByte)
			{ return m_Coders[GetState(pos, prevByte)].DecodeNormal(rangeDecoder); }

			public byte DecodeWithMatchByte(RangeCoder.Decoder rangeDecoder, uint pos, byte prevByte, byte matchByte)
			{ return m_Coders[GetState(pos, prevByte)].DecodeWithMatchByte(rangeDecoder, matchByte); }
		};

		LZ.OutWindow m_OutWindow = new LZ.OutWindow();
		RangeCoder.Decoder m_RangeDecoder = new RangeCoder.Decoder();

		BitDecoder[] m_IsMatchDecoders = new BitDecoder[Base.kNumStates << Base.kNumPosStatesBitsMax];
		BitDecoder[] m_IsRepDecoders = new BitDecoder[Base.kNumStates];
		BitDecoder[] m_IsRepG0Decoders = new BitDecoder[Base.kNumStates];
		BitDecoder[] m_IsRepG1Decoders = new BitDecoder[Base.kNumStates];
		BitDecoder[] m_IsRepG2Decoders = new BitDecoder[Base.kNumStates];
		BitDecoder[] m_IsRep0LongDecoders = new BitDecoder[Base.kNumStates << Base.kNumPosStatesBitsMax];

		BitTreeDecoder[] m_PosSlotDecoder = new BitTreeDecoder[Base.kNumLenToPosStates];
		BitDecoder[] m_PosDecoders = new BitDecoder[Base.kNumFullDistances - Base.kEndPosModelIndex];

		BitTreeDecoder m_PosAlignDecoder = new BitTreeDecoder(Base.kNumAlignBits);

		LenDecoder m_LenDecoder = new LenDecoder();
		LenDecoder m_RepLenDecoder = new LenDecoder();

		LiteralDecoder m_LiteralDecoder = new LiteralDecoder();

		uint m_DictionarySize;
		uint m_DictionarySizeCheck;

		uint m_PosStateMask;

		public Decoder()
		{
			m_DictionarySize = 0xFFFFFFFF;
			for (int i = 0; i < Base.kNumLenToPosStates; i++)
				m_PosSlotDecoder[i] = new BitTreeDecoder(Base.kNumPosSlotBits);
		}

		void SetDictionarySize(uint dictionarySize)
		{
			if (m_DictionarySize != dictionarySize)
			{
				m_DictionarySize = dictionarySize;
				m_DictionarySizeCheck = Math.Max(m_DictionarySize, 1);
				uint blockSize = Math.Max(m_DictionarySizeCheck, (1 << 12));
				m_OutWindow.Create(blockSize);
			}
		}

		void SetLiteralProperties(int lp, int lc)
		{
			if (lp > 8)
				throw new InvalidParamException();
			if (lc > 8)
				throw new InvalidParamException();
			m_LiteralDecoder.Create(lp, lc);
		}

		void SetPosBitsProperties(int pb)
		{
			if (pb > Base.kNumPosStatesBitsMax)
				throw new InvalidParamException();
			uint numPosStates = (uint)1 << pb;
			m_LenDecoder.Create(numPosStates);
			m_RepLenDecoder.Create(numPosStates);
			m_PosStateMask = numPosStates - 1;
		}

		bool _solid = false;
		void Init(System.IO.Stream inStream, System.IO.Stream outStream)
		{
			m_RangeDecoder.Init(inStream);
			m_OutWindow.Init(outStream, _solid);

			uint i;
			for (i = 0; i < Base.kNumStates; i++)
			{
				for (uint j = 0; j <= m_PosStateMask; j++)
				{
					uint index = (i << Base.kNumPosStatesBitsMax) + j;
					m_IsMatchDecoders[index].Init();
					m_IsRep0LongDecoders[index].Init();
				}
				m_IsRepDecoders[i].Init();
				m_IsRepG0Decoders[i].Init();
				m_IsRepG1Decoders[i].Init();
				m_IsRepG2Decoders[i].Init();
			}

			m_LiteralDecoder.Init();
			for (i = 0; i < Base.kNumLenToPosStates; i++)
				m_PosSlotDecoder[i].Init();
			// m_PosSpecDecoder.Init();
			for (i = 0; i < Base.kNumFullDistances - Base.kEndPosModelIndex; i++)
				m_PosDecoders[i].Init();

			m_LenDecoder.Init();
			m_RepLenDecoder.Init();
			m_PosAlignDecoder.Init();
		}

		public void Code(System.IO.Stream inStream, System.IO.Stream outStream,
			Int64 inSize, Int64 outSize, ICodeProgress progress)
		{
			Init(inStream, outStream);

			Base.State state = new Base.State();
			state.Init();
			uint rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0;

			UInt64 nowPos64 = 0;
			UInt64 outSize64 = (UInt64)outSize;
			if (nowPos64 < outSize64)
			{
				if (m_IsMatchDecoders[state.Index << Base.kNumPosStatesBitsMax].Decode(m_RangeDecoder) != 0)
					throw new DataErrorException();
				state.UpdateChar();
				byte b = m_LiteralDecoder.DecodeNormal(m_RangeDecoder, 0, 0);
				m_OutWindow.PutByte(b);
				nowPos64++;
			}
			while (nowPos64 < outSize64)
			{
				// UInt64 next = Math.Min(nowPos64 + (1 << 18), outSize64);
				// while(nowPos64 < next)
				{
					uint posState = (uint)nowPos64 & m_PosStateMask;
					if (m_IsMatchDecoders[(state.Index << Base.kNumPosStatesBitsMax) + posState].Decode(m_RangeDecoder) == 0)
					{
						byte b;
						byte prevByte = m_OutWindow.GetByte(0);
						if (!state.IsCharState())
							b = m_LiteralDecoder.DecodeWithMatchByte(m_RangeDecoder,
								(uint)nowPos64, prevByte, m_OutWindow.GetByte(rep0));
						else
							b = m_LiteralDecoder.DecodeNormal(m_RangeDecoder, (uint)nowPos64, prevByte);
						m_OutWindow.PutByte(b);
						state.UpdateChar();
						nowPos64++;
					}
					else
					{
						uint len;
						if (m_IsRepDecoders[state.Index].Decode(m_RangeDecoder) == 1)
						{
							if (m_IsRepG0Decoders[state.Index].Decode(m_RangeDecoder) == 0)
							{
								if (m_IsRep0LongDecoders[(state.Index << Base.kNumPosStatesBitsMax) + posState].Decode(m_RangeDecoder) == 0)
								{
									state.UpdateShortRep();
									m_OutWindow.PutByte(m_OutWindow.GetByte(rep0));
									nowPos64++;
									continue;
								}
							}
							else
							{
								UInt32 distance;
								if (m_IsRepG1Decoders[state.Index].Decode(m_RangeDecoder) == 0)
								{
									distance = rep1;
								}
								else
								{
									if (m_IsRepG2Decoders[state.Index].Decode(m_RangeDecoder) == 0)
										distance = rep2;
									else
									{
										distance = rep3;
										rep3 = rep2;
									}
									rep2 = rep1;
								}
								rep1 = rep0;
								rep0 = distance;
							}
							len = m_RepLenDecoder.Decode(m_RangeDecoder, posState) + Base.kMatchMinLen;
							state.UpdateRep();
						}
						else
						{
							rep3 = rep2;
							rep2 = rep1;
							rep1 = rep0;
							len = Base.kMatchMinLen + m_LenDecoder.Decode(m_RangeDecoder, posState);
							state.UpdateMatch();
							uint posSlot = m_PosSlotDecoder[Base.GetLenToPosState(len)].Decode(m_RangeDecoder);
							if (posSlot >= Base.kStartPosModelIndex)
							{
								int numDirectBits = (int)((posSlot >> 1) - 1);
								rep0 = ((2 | (posSlot & 1)) << numDirectBits);
								if (posSlot < Base.kEndPosModelIndex)
									rep0 += BitTreeDecoder.ReverseDecode(m_PosDecoders,
											rep0 - posSlot - 1, m_RangeDecoder, numDirectBits);
								else
								{
									rep0 += (m_RangeDecoder.DecodeDirectBits(
										numDirectBits - Base.kNumAlignBits) << Base.kNumAlignBits);
									rep0 += m_PosAlignDecoder.ReverseDecode(m_RangeDecoder);
								}
							}
							else
								rep0 = posSlot;
						}
						if (rep0 >= m_OutWindow.TrainSize + nowPos64 || rep0 >= m_DictionarySizeCheck)
						{
							if (rep0 == 0xFFFFFFFF)
								break;
							throw new DataErrorException();
						}
						m_OutWindow.CopyBlock(rep0, len);
						nowPos64 += len;
					}
				}
			}
			m_OutWindow.Flush();
			m_OutWindow.ReleaseStream();
			m_RangeDecoder.ReleaseStream();
		}

		public void SetDecoderProperties(byte[] properties)
		{
			if (properties.Length < 5)
				throw new InvalidParamException();
			int lc = properties[0] % 9;
			int remainder = properties[0] / 9;
			int lp = remainder % 5;
			int pb = remainder / 5;
			if (pb > Base.kNumPosStatesBitsMax)
				throw new InvalidParamException();
			UInt32 dictionarySize = 0;
			for (int i = 0; i < 4; i++)
				dictionarySize += ((UInt32)(properties[1 + i])) << (i * 8);
			SetDictionarySize(dictionarySize);
			SetLiteralProperties(lp, lc);
			SetPosBitsProperties(pb);
		}

		public bool Train(System.IO.Stream stream)
		{
			_solid = true;
			return m_OutWindow.Train(stream);
		}

		/*
		public override bool CanRead { get { return true; }}
		public override bool CanWrite { get { return true; }}
		public override bool CanSeek { get { return true; }}
		public override long Length { get { return 0; }}
		public override long Position
		{
			get { return 0;	}
			set { }
		}
		public override void Flush() { }
		public override int Read(byte[] buffer, int offset, int count)
		{
			return 0;
		}
		public override void Write(byte[] buffer, int offset, int count)
		{
		}
		public override long Seek(long offset, System.IO.SeekOrigin origin)
		{
			return 0;
		}
		public override void SetLength(long value) {}
		*/
	}
}

namespace SevenZip.Compression.LZ
{
	public class InWindow
	{
		public Byte[] _bufferBase = null; // pointer to buffer with data
		System.IO.Stream _stream;
		UInt32 _posLimit; // offset (from _buffer) of first byte when new block reading must be done
		bool _streamEndWasReached; // if (true) then _streamPos shows real end of stream

		UInt32 _pointerToLastSafePosition;

		public UInt32 _bufferOffset;

		public UInt32 _blockSize; // Size of Allocated memory block
		public UInt32 _pos; // offset (from _buffer) of curent byte
		UInt32 _keepSizeBefore; // how many BYTEs must be kept in buffer before _pos
		UInt32 _keepSizeAfter; // how many BYTEs must be kept buffer after _pos
		public UInt32 _streamPos; // offset (from _buffer) of first not read byte from Stream

		public void MoveBlock()
		{
			UInt32 offset = (UInt32)(_bufferOffset) + _pos - _keepSizeBefore;
			// we need one additional byte, since MovePos moves on 1 byte.
			if (offset > 0)
				offset--;

			UInt32 numBytes = (UInt32)(_bufferOffset) + _streamPos - offset;

			// check negative offset ????
			for (UInt32 i = 0; i < numBytes; i++)
				_bufferBase[i] = _bufferBase[offset + i];
			_bufferOffset -= offset;
		}

		public virtual void ReadBlock()
		{
			if (_streamEndWasReached)
				return;
			while (true)
			{
				int size = (int)((0 - _bufferOffset) + _blockSize - _streamPos);
				if (size == 0)
					return;
				int numReadBytes = _stream.Read(_bufferBase, (int)(_bufferOffset + _streamPos), size);
				if (numReadBytes == 0)
				{
					_posLimit = _streamPos;
					UInt32 pointerToPostion = _bufferOffset + _posLimit;
					if (pointerToPostion > _pointerToLastSafePosition)
						_posLimit = (UInt32)(_pointerToLastSafePosition - _bufferOffset);

					_streamEndWasReached = true;
					return;
				}
				_streamPos += (UInt32)numReadBytes;
				if (_streamPos >= _pos + _keepSizeAfter)
					_posLimit = _streamPos - _keepSizeAfter;
			}
		}

		void Free() { _bufferBase = null; }

		public void Create(UInt32 keepSizeBefore, UInt32 keepSizeAfter, UInt32 keepSizeReserv)
		{
			_keepSizeBefore = keepSizeBefore;
			_keepSizeAfter = keepSizeAfter;
			UInt32 blockSize = keepSizeBefore + keepSizeAfter + keepSizeReserv;
			if (_bufferBase == null || _blockSize != blockSize)
			{
				Free();
				_blockSize = blockSize;
				_bufferBase = new Byte[_blockSize];
			}
			_pointerToLastSafePosition = _blockSize - keepSizeAfter;
		}

		public void SetStream(System.IO.Stream stream) { _stream = stream; }
		public void ReleaseStream() { _stream = null; }

		public void Init()
		{
			_bufferOffset = 0;
			_pos = 0;
			_streamPos = 0;
			_streamEndWasReached = false;
			ReadBlock();
		}

		public void MovePos()
		{
			_pos++;
			if (_pos > _posLimit)
			{
				UInt32 pointerToPostion = _bufferOffset + _pos;
				if (pointerToPostion > _pointerToLastSafePosition)
					MoveBlock();
				ReadBlock();
			}
		}

		public Byte GetIndexByte(Int32 index) { return _bufferBase[_bufferOffset + _pos + index]; }

		// index + limit have not to exceed _keepSizeAfter;
		public UInt32 GetMatchLen(Int32 index, UInt32 distance, UInt32 limit)
		{
			if (_streamEndWasReached)
				if ((_pos + index) + limit > _streamPos)
					limit = _streamPos - (UInt32)(_pos + index);
			distance++;
			// Byte *pby = _buffer + (size_t)_pos + index;
			UInt32 pby = _bufferOffset + _pos + (UInt32)index;

			UInt32 i;
			for (i = 0; i < limit && _bufferBase[pby + i] == _bufferBase[pby + i - distance]; i++) ;
			return i;
		}

		public UInt32 GetNumAvailableBytes() { return _streamPos - _pos; }

		public void ReduceOffsets(Int32 subValue)
		{
			_bufferOffset += (UInt32)subValue;
			_posLimit -= (UInt32)subValue;
			_pos -= (UInt32)subValue;
			_streamPos -= (UInt32)subValue;
		}
	}
}

namespace SevenZip
{
	class CRC
	{
		public static readonly uint[] Table;

		static CRC()
		{
			Table = new uint[256];
			const uint kPoly = 0xEDB88320;
			for (uint i = 0; i < 256; i++)
			{
				uint r = i;
				for (int j = 0; j < 8; j++)
					if ((r & 1) != 0)
						r = (r >> 1) ^ kPoly;
					else
						r >>= 1;
				Table[i] = r;
			}
		}

		uint _value = 0xFFFFFFFF;

		public void Init() { _value = 0xFFFFFFFF; }

		public void UpdateByte(byte b)
		{
			_value = Table[(((byte)(_value)) ^ b)] ^ (_value >> 8);
		}

		public void Update(byte[] data, uint offset, uint size)
		{
			for (uint i = 0; i < size; i++)
				_value = Table[(((byte)(_value)) ^ data[offset + i])] ^ (_value >> 8);
		}

		public uint GetDigest() { return _value ^ 0xFFFFFFFF; }

		static uint CalculateDigest(byte[] data, uint offset, uint size)
		{
			CRC crc = new CRC();
			// crc.Init();
			crc.Update(data, offset, size);
			return crc.GetDigest();
		}

		static bool VerifyDigest(uint digest, byte[] data, uint offset, uint size)
		{
			return (CalculateDigest(data, offset, size) == digest);
		}
	}
}

namespace SevenZip.Compression.LZ
{
	public class BinTree : InWindow, IMatchFinder
	{
		UInt32 _cyclicBufferPos;
		UInt32 _cyclicBufferSize = 0;
		UInt32 _matchMaxLen;

		UInt32[] _son;
		UInt32[] _hash;

		UInt32 _cutValue = 0xFF;
		UInt32 _hashMask;
		UInt32 _hashSizeSum = 0;

		bool HASH_ARRAY = true;

		const UInt32 kHash2Size = 1 << 10;
		const UInt32 kHash3Size = 1 << 16;
		const UInt32 kBT2HashSize = 1 << 16;
		const UInt32 kStartMaxLen = 1;
		const UInt32 kHash3Offset = kHash2Size;
		const UInt32 kEmptyHashValue = 0;
		const UInt32 kMaxValForNormalize = ((UInt32)1 << 31) - 1;

		UInt32 kNumHashDirectBytes = 0;
		UInt32 kMinMatchCheck = 4;
		UInt32 kFixHashSize = kHash2Size + kHash3Size;

		public void SetType(int numHashBytes)
		{
			HASH_ARRAY = (numHashBytes > 2);
			if (HASH_ARRAY)
			{
				kNumHashDirectBytes = 0;
				kMinMatchCheck = 4;
				kFixHashSize = kHash2Size + kHash3Size;
			}
			else
			{
				kNumHashDirectBytes = 2;
				kMinMatchCheck = 2 + 1;
				kFixHashSize = 0;
			}
		}

		public new void SetStream(System.IO.Stream stream) { base.SetStream(stream); }
		public new void ReleaseStream() { base.ReleaseStream(); }

		public new void Init()
		{
			base.Init();
			for (UInt32 i = 0; i < _hashSizeSum; i++)
				_hash[i] = kEmptyHashValue;
			_cyclicBufferPos = 0;
			ReduceOffsets(-1);
		}

		public new void MovePos()
		{
			if (++_cyclicBufferPos >= _cyclicBufferSize)
				_cyclicBufferPos = 0;
			base.MovePos();
			if (_pos == kMaxValForNormalize)
				Normalize();
		}

		public new Byte GetIndexByte(Int32 index) { return base.GetIndexByte(index); }

		public new UInt32 GetMatchLen(Int32 index, UInt32 distance, UInt32 limit)
		{ return base.GetMatchLen(index, distance, limit); }

		public new UInt32 GetNumAvailableBytes() { return base.GetNumAvailableBytes(); }

		public void Create(UInt32 historySize, UInt32 keepAddBufferBefore,
				UInt32 matchMaxLen, UInt32 keepAddBufferAfter)
		{
			if (historySize > kMaxValForNormalize - 256)
				throw new Exception();
			_cutValue = 16 + (matchMaxLen >> 1);

			UInt32 windowReservSize = (historySize + keepAddBufferBefore +
					matchMaxLen + keepAddBufferAfter) / 2 + 256;

			base.Create(historySize + keepAddBufferBefore, matchMaxLen + keepAddBufferAfter, windowReservSize);

			_matchMaxLen = matchMaxLen;

			UInt32 cyclicBufferSize = historySize + 1;
			if (_cyclicBufferSize != cyclicBufferSize)
				_son = new UInt32[(_cyclicBufferSize = cyclicBufferSize) * 2];

			UInt32 hs = kBT2HashSize;

			if (HASH_ARRAY)
			{
				hs = historySize - 1;
				hs |= (hs >> 1);
				hs |= (hs >> 2);
				hs |= (hs >> 4);
				hs |= (hs >> 8);
				hs >>= 1;
				hs |= 0xFFFF;
				if (hs > (1 << 24))
					hs >>= 1;
				_hashMask = hs;
				hs++;
				hs += kFixHashSize;
			}
			if (hs != _hashSizeSum)
				_hash = new UInt32[_hashSizeSum = hs];
		}

		public UInt32 GetMatches(UInt32[] distances)
		{
			UInt32 lenLimit;
			if (_pos + _matchMaxLen <= _streamPos)
				lenLimit = _matchMaxLen;
			else
			{
				lenLimit = _streamPos - _pos;
				if (lenLimit < kMinMatchCheck)
				{
					MovePos();
					return 0;
				}
			}

			UInt32 offset = 0;
			UInt32 matchMinPos = (_pos > _cyclicBufferSize) ? (_pos - _cyclicBufferSize) : 0;
			UInt32 cur = _bufferOffset + _pos;
			UInt32 maxLen = kStartMaxLen; // to avoid items for len < hashSize;
			UInt32 hashValue, hash2Value = 0, hash3Value = 0;

			if (HASH_ARRAY)
			{
				UInt32 temp = CRC.Table[_bufferBase[cur]] ^ _bufferBase[cur + 1];
				hash2Value = temp & (kHash2Size - 1);
				temp ^= ((UInt32)(_bufferBase[cur + 2]) << 8);
				hash3Value = temp & (kHash3Size - 1);
				hashValue = (temp ^ (CRC.Table[_bufferBase[cur + 3]] << 5)) & _hashMask;
			}
			else
				hashValue = _bufferBase[cur] ^ ((UInt32)(_bufferBase[cur + 1]) << 8);

			UInt32 curMatch = _hash[kFixHashSize + hashValue];
			if (HASH_ARRAY)
			{
				UInt32 curMatch2 = _hash[hash2Value];
				UInt32 curMatch3 = _hash[kHash3Offset + hash3Value];
				_hash[hash2Value] = _pos;
				_hash[kHash3Offset + hash3Value] = _pos;
				if (curMatch2 > matchMinPos)
					if (_bufferBase[_bufferOffset + curMatch2] == _bufferBase[cur])
					{
						distances[offset++] = maxLen = 2;
						distances[offset++] = _pos - curMatch2 - 1;
					}
				if (curMatch3 > matchMinPos)
					if (_bufferBase[_bufferOffset + curMatch3] == _bufferBase[cur])
					{
						if (curMatch3 == curMatch2)
							offset -= 2;
						distances[offset++] = maxLen = 3;
						distances[offset++] = _pos - curMatch3 - 1;
						curMatch2 = curMatch3;
					}
				if (offset != 0 && curMatch2 == curMatch)
				{
					offset -= 2;
					maxLen = kStartMaxLen;
				}
			}

			_hash[kFixHashSize + hashValue] = _pos;

			UInt32 ptr0 = (_cyclicBufferPos << 1) + 1;
			UInt32 ptr1 = (_cyclicBufferPos << 1);

			UInt32 len0, len1;
			len0 = len1 = kNumHashDirectBytes;

			if (kNumHashDirectBytes != 0)
			{
				if (curMatch > matchMinPos)
				{
					if (_bufferBase[_bufferOffset + curMatch + kNumHashDirectBytes] !=
							_bufferBase[cur + kNumHashDirectBytes])
					{
						distances[offset++] = maxLen = kNumHashDirectBytes;
						distances[offset++] = _pos - curMatch - 1;
					}
				}
			}

			UInt32 count = _cutValue;

			while (true)
			{
				if (curMatch <= matchMinPos || count-- == 0)
				{
					_son[ptr0] = _son[ptr1] = kEmptyHashValue;
					break;
				}
				UInt32 delta = _pos - curMatch;
				UInt32 cyclicPos = ((delta <= _cyclicBufferPos) ?
							(_cyclicBufferPos - delta) :
							(_cyclicBufferPos - delta + _cyclicBufferSize)) << 1;

				UInt32 pby1 = _bufferOffset + curMatch;
				UInt32 len = Math.Min(len0, len1);
				if (_bufferBase[pby1 + len] == _bufferBase[cur + len])
				{
					while (++len != lenLimit)
						if (_bufferBase[pby1 + len] != _bufferBase[cur + len])
							break;
					if (maxLen < len)
					{
						distances[offset++] = maxLen = len;
						distances[offset++] = delta - 1;
						if (len == lenLimit)
						{
							_son[ptr1] = _son[cyclicPos];
							_son[ptr0] = _son[cyclicPos + 1];
							break;
						}
					}
				}
				if (_bufferBase[pby1 + len] < _bufferBase[cur + len])
				{
					_son[ptr1] = curMatch;
					ptr1 = cyclicPos + 1;
					curMatch = _son[ptr1];
					len1 = len;
				}
				else
				{
					_son[ptr0] = curMatch;
					ptr0 = cyclicPos;
					curMatch = _son[ptr0];
					len0 = len;
				}
			}
			MovePos();
			return offset;
		}

		public void Skip(UInt32 num)
		{
			do
			{
				UInt32 lenLimit;
				if (_pos + _matchMaxLen <= _streamPos)
					lenLimit = _matchMaxLen;
				else
				{
					lenLimit = _streamPos - _pos;
					if (lenLimit < kMinMatchCheck)
					{
						MovePos();
						continue;
					}
				}

				UInt32 matchMinPos = (_pos > _cyclicBufferSize) ? (_pos - _cyclicBufferSize) : 0;
				UInt32 cur = _bufferOffset + _pos;

				UInt32 hashValue;

				if (HASH_ARRAY)
				{
					UInt32 temp = CRC.Table[_bufferBase[cur]] ^ _bufferBase[cur + 1];
					UInt32 hash2Value = temp & (kHash2Size - 1);
					_hash[hash2Value] = _pos;
					temp ^= ((UInt32)(_bufferBase[cur + 2]) << 8);
					UInt32 hash3Value = temp & (kHash3Size - 1);
					_hash[kHash3Offset + hash3Value] = _pos;
					hashValue = (temp ^ (CRC.Table[_bufferBase[cur + 3]] << 5)) & _hashMask;
				}
				else
					hashValue = _bufferBase[cur] ^ ((UInt32)(_bufferBase[cur + 1]) << 8);

				UInt32 curMatch = _hash[kFixHashSize + hashValue];
				_hash[kFixHashSize + hashValue] = _pos;

				UInt32 ptr0 = (_cyclicBufferPos << 1) + 1;
				UInt32 ptr1 = (_cyclicBufferPos << 1);

				UInt32 len0, len1;
				len0 = len1 = kNumHashDirectBytes;

				UInt32 count = _cutValue;
				while (true)
				{
					if (curMatch <= matchMinPos || count-- == 0)
					{
						_son[ptr0] = _son[ptr1] = kEmptyHashValue;
						break;
					}

					UInt32 delta = _pos - curMatch;
					UInt32 cyclicPos = ((delta <= _cyclicBufferPos) ?
								(_cyclicBufferPos - delta) :
								(_cyclicBufferPos - delta + _cyclicBufferSize)) << 1;

					UInt32 pby1 = _bufferOffset + curMatch;
					UInt32 len = Math.Min(len0, len1);
					if (_bufferBase[pby1 + len] == _bufferBase[cur + len])
					{
						while (++len != lenLimit)
							if (_bufferBase[pby1 + len] != _bufferBase[cur + len])
								break;
						if (len == lenLimit)
						{
							_son[ptr1] = _son[cyclicPos];
							_son[ptr0] = _son[cyclicPos + 1];
							break;
						}
					}
					if (_bufferBase[pby1 + len] < _bufferBase[cur + len])
					{
						_son[ptr1] = curMatch;
						ptr1 = cyclicPos + 1;
						curMatch = _son[ptr1];
						len1 = len;
					}
					else
					{
						_son[ptr0] = curMatch;
						ptr0 = cyclicPos;
						curMatch = _son[ptr0];
						len0 = len;
					}
				}
				MovePos();
			}
			while (--num != 0);
		}

		void NormalizeLinks(UInt32[] items, UInt32 numItems, UInt32 subValue)
		{
			for (UInt32 i = 0; i < numItems; i++)
			{
				UInt32 value = items[i];
				if (value <= subValue)
					value = kEmptyHashValue;
				else
					value -= subValue;
				items[i] = value;
			}
		}

		void Normalize()
		{
			UInt32 subValue = _pos - _cyclicBufferSize;
			NormalizeLinks(_son, _cyclicBufferSize * 2, subValue);
			NormalizeLinks(_hash, _hashSizeSum, subValue);
			ReduceOffsets((Int32)subValue);
		}

		public void SetCutValue(UInt32 cutValue) { _cutValue = cutValue; }
	}
}

namespace SevenZip.Compression.LZ
{
	interface IInWindowStream
	{
		void SetStream(System.IO.Stream inStream);
		void Init();
		void ReleaseStream();
		Byte GetIndexByte(Int32 index);
		UInt32 GetMatchLen(Int32 index, UInt32 distance, UInt32 limit);
		UInt32 GetNumAvailableBytes();
	}

	interface IMatchFinder : IInWindowStream
	{
		void Create(UInt32 historySize, UInt32 keepAddBufferBefore,
				UInt32 matchMaxLen, UInt32 keepAddBufferAfter);
		UInt32 GetMatches(UInt32[] distances);
		void Skip(UInt32 num);
	}
}

namespace SevenZip.Compression.LZMA
{
	using RangeCoder;

	public class Encoder : ICoder, ISetCoderProperties, IWriteCoderProperties
	{
		enum EMatchFinderType
		{
			BT2,
			BT4,
		};

		const UInt32 kIfinityPrice = 0xFFFFFFF;

		static Byte[] g_FastPos = new Byte[1 << 11];

		static Encoder()
		{
			const Byte kFastSlots = 22;
			int c = 2;
			g_FastPos[0] = 0;
			g_FastPos[1] = 1;
			for (Byte slotFast = 2; slotFast < kFastSlots; slotFast++)
			{
				UInt32 k = ((UInt32)1 << ((slotFast >> 1) - 1));
				for (UInt32 j = 0; j < k; j++, c++)
					g_FastPos[c] = slotFast;
			}
		}

		static UInt32 GetPosSlot(UInt32 pos)
		{
			if (pos < (1 << 11))
				return g_FastPos[pos];
			if (pos < (1 << 21))
				return (UInt32)(g_FastPos[pos >> 10] + 20);
			return (UInt32)(g_FastPos[pos >> 20] + 40);
		}

		static UInt32 GetPosSlot2(UInt32 pos)
		{
			if (pos < (1 << 17))
				return (UInt32)(g_FastPos[pos >> 6] + 12);
			if (pos < (1 << 27))
				return (UInt32)(g_FastPos[pos >> 16] + 32);
			return (UInt32)(g_FastPos[pos >> 26] + 52);
		}

		Base.State _state = new Base.State();
		Byte _previousByte;
		UInt32[] _repDistances = new UInt32[Base.kNumRepDistances];

		void BaseInit()
		{
			_state.Init();
			_previousByte = 0;
			for (UInt32 i = 0; i < Base.kNumRepDistances; i++)
				_repDistances[i] = 0;
		}

		const int kDefaultDictionaryLogSize = 22;
		const UInt32 kNumFastBytesDefault = 0x20;

		class LiteralEncoder
		{
			public struct Encoder2
			{
				BitEncoder[] m_Encoders;

				public void Create() { m_Encoders = new BitEncoder[0x300]; }

				public void Init() { for (int i = 0; i < 0x300; i++) m_Encoders[i].Init(); }

				public void Encode(RangeCoder.Encoder rangeEncoder, byte symbol)
				{
					uint context = 1;
					for (int i = 7; i >= 0; i--)
					{
						uint bit = (uint)((symbol >> i) & 1);
						m_Encoders[context].Encode(rangeEncoder, bit);
						context = (context << 1) | bit;
					}
				}

				public void EncodeMatched(RangeCoder.Encoder rangeEncoder, byte matchByte, byte symbol)
				{
					uint context = 1;
					bool same = true;
					for (int i = 7; i >= 0; i--)
					{
						uint bit = (uint)((symbol >> i) & 1);
						uint state = context;
						if (same)
						{
							uint matchBit = (uint)((matchByte >> i) & 1);
							state += ((1 + matchBit) << 8);
							same = (matchBit == bit);
						}
						m_Encoders[state].Encode(rangeEncoder, bit);
						context = (context << 1) | bit;
					}
				}

				public uint GetPrice(bool matchMode, byte matchByte, byte symbol)
				{
					uint price = 0;
					uint context = 1;
					int i = 7;
					if (matchMode)
					{
						for (; i >= 0; i--)
						{
							uint matchBit = (uint)(matchByte >> i) & 1;
							uint bit = (uint)(symbol >> i) & 1;
							price += m_Encoders[((1 + matchBit) << 8) + context].GetPrice(bit);
							context = (context << 1) | bit;
							if (matchBit != bit)
							{
								i--;
								break;
							}
						}
					}
					for (; i >= 0; i--)
					{
						uint bit = (uint)(symbol >> i) & 1;
						price += m_Encoders[context].GetPrice(bit);
						context = (context << 1) | bit;
					}
					return price;
				}
			}

			Encoder2[] m_Coders;
			int m_NumPrevBits;
			int m_NumPosBits;
			uint m_PosMask;

			public void Create(int numPosBits, int numPrevBits)
			{
				if (m_Coders != null && m_NumPrevBits == numPrevBits && m_NumPosBits == numPosBits)
					return;
				m_NumPosBits = numPosBits;
				m_PosMask = ((uint)1 << numPosBits) - 1;
				m_NumPrevBits = numPrevBits;
				uint numStates = (uint)1 << (m_NumPrevBits + m_NumPosBits);
				m_Coders = new Encoder2[numStates];
				for (uint i = 0; i < numStates; i++)
					m_Coders[i].Create();
			}

			public void Init()
			{
				uint numStates = (uint)1 << (m_NumPrevBits + m_NumPosBits);
				for (uint i = 0; i < numStates; i++)
					m_Coders[i].Init();
			}

			public Encoder2 GetSubCoder(UInt32 pos, Byte prevByte)
			{ return m_Coders[((pos & m_PosMask) << m_NumPrevBits) + (uint)(prevByte >> (8 - m_NumPrevBits))]; }
		}

		class LenEncoder
		{
			RangeCoder.BitEncoder _choice = new RangeCoder.BitEncoder();
			RangeCoder.BitEncoder _choice2 = new RangeCoder.BitEncoder();
			RangeCoder.BitTreeEncoder[] _lowCoder = new RangeCoder.BitTreeEncoder[Base.kNumPosStatesEncodingMax];
			RangeCoder.BitTreeEncoder[] _midCoder = new RangeCoder.BitTreeEncoder[Base.kNumPosStatesEncodingMax];
			RangeCoder.BitTreeEncoder _highCoder = new RangeCoder.BitTreeEncoder(Base.kNumHighLenBits);

			public LenEncoder()
			{
				for (UInt32 posState = 0; posState < Base.kNumPosStatesEncodingMax; posState++)
				{
					_lowCoder[posState] = new RangeCoder.BitTreeEncoder(Base.kNumLowLenBits);
					_midCoder[posState] = new RangeCoder.BitTreeEncoder(Base.kNumMidLenBits);
				}
			}

			public void Init(UInt32 numPosStates)
			{
				_choice.Init();
				_choice2.Init();
				for (UInt32 posState = 0; posState < numPosStates; posState++)
				{
					_lowCoder[posState].Init();
					_midCoder[posState].Init();
				}
				_highCoder.Init();
			}

			public void Encode(RangeCoder.Encoder rangeEncoder, UInt32 symbol, UInt32 posState)
			{
				if (symbol < Base.kNumLowLenSymbols)
				{
					_choice.Encode(rangeEncoder, 0);
					_lowCoder[posState].Encode(rangeEncoder, symbol);
				}
				else
				{
					symbol -= Base.kNumLowLenSymbols;
					_choice.Encode(rangeEncoder, 1);
					if (symbol < Base.kNumMidLenSymbols)
					{
						_choice2.Encode(rangeEncoder, 0);
						_midCoder[posState].Encode(rangeEncoder, symbol);
					}
					else
					{
						_choice2.Encode(rangeEncoder, 1);
						_highCoder.Encode(rangeEncoder, symbol - Base.kNumMidLenSymbols);
					}
				}
			}

			public void SetPrices(UInt32 posState, UInt32 numSymbols, UInt32[] prices, UInt32 st)
			{
				UInt32 a0 = _choice.GetPrice0();
				UInt32 a1 = _choice.GetPrice1();
				UInt32 b0 = a1 + _choice2.GetPrice0();
				UInt32 b1 = a1 + _choice2.GetPrice1();
				UInt32 i = 0;
				for (i = 0; i < Base.kNumLowLenSymbols; i++)
				{
					if (i >= numSymbols)
						return;
					prices[st + i] = a0 + _lowCoder[posState].GetPrice(i);
				}
				for (; i < Base.kNumLowLenSymbols + Base.kNumMidLenSymbols; i++)
				{
					if (i >= numSymbols)
						return;
					prices[st + i] = b0 + _midCoder[posState].GetPrice(i - Base.kNumLowLenSymbols);
				}
				for (; i < numSymbols; i++)
					prices[st + i] = b1 + _highCoder.GetPrice(i - Base.kNumLowLenSymbols - Base.kNumMidLenSymbols);
			}
		};

		const UInt32 kNumLenSpecSymbols = Base.kNumLowLenSymbols + Base.kNumMidLenSymbols;

		class LenPriceTableEncoder : LenEncoder
		{
			UInt32[] _prices = new UInt32[Base.kNumLenSymbols << Base.kNumPosStatesBitsEncodingMax];
			UInt32 _tableSize;
			UInt32[] _counters = new UInt32[Base.kNumPosStatesEncodingMax];

			public void SetTableSize(UInt32 tableSize) { _tableSize = tableSize; }

			public UInt32 GetPrice(UInt32 symbol, UInt32 posState)
			{
				return _prices[posState * Base.kNumLenSymbols + symbol];
			}

			void UpdateTable(UInt32 posState)
			{
				SetPrices(posState, _tableSize, _prices, posState * Base.kNumLenSymbols);
				_counters[posState] = _tableSize;
			}

			public void UpdateTables(UInt32 numPosStates)
			{
				for (UInt32 posState = 0; posState < numPosStates; posState++)
					UpdateTable(posState);
			}

			public new void Encode(RangeCoder.Encoder rangeEncoder, UInt32 symbol, UInt32 posState)
			{
				base.Encode(rangeEncoder, symbol, posState);
				if (--_counters[posState] == 0)
					UpdateTable(posState);
			}
		}

		const UInt32 kNumOpts = 1 << 12;
		class Optimal
		{
			public Base.State State;

			public bool Prev1IsChar;
			public bool Prev2;

			public UInt32 PosPrev2;
			public UInt32 BackPrev2;

			public UInt32 Price;
			public UInt32 PosPrev;
			public UInt32 BackPrev;

			public UInt32 Backs0;
			public UInt32 Backs1;
			public UInt32 Backs2;
			public UInt32 Backs3;

			public void MakeAsChar() { BackPrev = 0xFFFFFFFF; Prev1IsChar = false; }
			public void MakeAsShortRep() { BackPrev = 0; ; Prev1IsChar = false; }
			public bool IsShortRep() { return (BackPrev == 0); }
		};
		Optimal[] _optimum = new Optimal[kNumOpts];
		LZ.IMatchFinder _matchFinder = null;
		RangeCoder.Encoder _rangeEncoder = new RangeCoder.Encoder();

		RangeCoder.BitEncoder[] _isMatch = new RangeCoder.BitEncoder[Base.kNumStates << Base.kNumPosStatesBitsMax];
		RangeCoder.BitEncoder[] _isRep = new RangeCoder.BitEncoder[Base.kNumStates];
		RangeCoder.BitEncoder[] _isRepG0 = new RangeCoder.BitEncoder[Base.kNumStates];
		RangeCoder.BitEncoder[] _isRepG1 = new RangeCoder.BitEncoder[Base.kNumStates];
		RangeCoder.BitEncoder[] _isRepG2 = new RangeCoder.BitEncoder[Base.kNumStates];
		RangeCoder.BitEncoder[] _isRep0Long = new RangeCoder.BitEncoder[Base.kNumStates << Base.kNumPosStatesBitsMax];

		RangeCoder.BitTreeEncoder[] _posSlotEncoder = new RangeCoder.BitTreeEncoder[Base.kNumLenToPosStates];

		RangeCoder.BitEncoder[] _posEncoders = new RangeCoder.BitEncoder[Base.kNumFullDistances - Base.kEndPosModelIndex];
		RangeCoder.BitTreeEncoder _posAlignEncoder = new RangeCoder.BitTreeEncoder(Base.kNumAlignBits);

		LenPriceTableEncoder _lenEncoder = new LenPriceTableEncoder();
		LenPriceTableEncoder _repMatchLenEncoder = new LenPriceTableEncoder();

		LiteralEncoder _literalEncoder = new LiteralEncoder();

		UInt32[] _matchDistances = new UInt32[Base.kMatchMaxLen * 2 + 2];

		UInt32 _numFastBytes = kNumFastBytesDefault;
		UInt32 _longestMatchLength;
		UInt32 _numDistancePairs;

		UInt32 _additionalOffset;

		UInt32 _optimumEndIndex;
		UInt32 _optimumCurrentIndex;

		bool _longestMatchWasFound;

		UInt32[] _posSlotPrices = new UInt32[1 << (Base.kNumPosSlotBits + Base.kNumLenToPosStatesBits)];
		UInt32[] _distancesPrices = new UInt32[Base.kNumFullDistances << Base.kNumLenToPosStatesBits];
		UInt32[] _alignPrices = new UInt32[Base.kAlignTableSize];
		UInt32 _alignPriceCount;

		UInt32 _distTableSize = (kDefaultDictionaryLogSize * 2);

		int _posStateBits = 2;
		UInt32 _posStateMask = (4 - 1);
		int _numLiteralPosStateBits = 0;
		int _numLiteralContextBits = 3;

		UInt32 _dictionarySize = (1 << kDefaultDictionaryLogSize);
		UInt32 _dictionarySizePrev = 0xFFFFFFFF;
		UInt32 _numFastBytesPrev = 0xFFFFFFFF;

		Int64 nowPos64;
		bool _finished;
		System.IO.Stream _inStream;

		EMatchFinderType _matchFinderType = EMatchFinderType.BT4;
		bool _writeEndMark = false;

		bool _needReleaseMFStream;

		void Create()
		{
			if (_matchFinder == null)
			{
				LZ.BinTree bt = new LZ.BinTree();
				int numHashBytes = 4;
				if (_matchFinderType == EMatchFinderType.BT2)
					numHashBytes = 2;
				bt.SetType(numHashBytes);
				_matchFinder = bt;
			}
			_literalEncoder.Create(_numLiteralPosStateBits, _numLiteralContextBits);

			if (_dictionarySize == _dictionarySizePrev && _numFastBytesPrev == _numFastBytes)
				return;
			_matchFinder.Create(_dictionarySize, kNumOpts, _numFastBytes, Base.kMatchMaxLen + 1);
			_dictionarySizePrev = _dictionarySize;
			_numFastBytesPrev = _numFastBytes;
		}

		public Encoder()
		{
			for (int i = 0; i < kNumOpts; i++)
				_optimum[i] = new Optimal();
			for (int i = 0; i < Base.kNumLenToPosStates; i++)
				_posSlotEncoder[i] = new RangeCoder.BitTreeEncoder(Base.kNumPosSlotBits);
		}

		void SetWriteEndMarkerMode(bool writeEndMarker)
		{
			_writeEndMark = writeEndMarker;
		}

		void Init()
		{
			BaseInit();
			_rangeEncoder.Init();

			uint i;
			for (i = 0; i < Base.kNumStates; i++)
			{
				for (uint j = 0; j <= _posStateMask; j++)
				{
					uint complexState = (i << Base.kNumPosStatesBitsMax) + j;
					_isMatch[complexState].Init();
					_isRep0Long[complexState].Init();
				}
				_isRep[i].Init();
				_isRepG0[i].Init();
				_isRepG1[i].Init();
				_isRepG2[i].Init();
			}
			_literalEncoder.Init();
			for (i = 0; i < Base.kNumLenToPosStates; i++)
				_posSlotEncoder[i].Init();
			for (i = 0; i < Base.kNumFullDistances - Base.kEndPosModelIndex; i++)
				_posEncoders[i].Init();

			_lenEncoder.Init((UInt32)1 << _posStateBits);
			_repMatchLenEncoder.Init((UInt32)1 << _posStateBits);

			_posAlignEncoder.Init();

			_longestMatchWasFound = false;
			_optimumEndIndex = 0;
			_optimumCurrentIndex = 0;
			_additionalOffset = 0;
		}

		void ReadMatchDistances(out UInt32 lenRes, out UInt32 numDistancePairs)
		{
			lenRes = 0;
			numDistancePairs = _matchFinder.GetMatches(_matchDistances);
			if (numDistancePairs > 0)
			{
				lenRes = _matchDistances[numDistancePairs - 2];
				if (lenRes == _numFastBytes)
					lenRes += _matchFinder.GetMatchLen((int)lenRes - 1, _matchDistances[numDistancePairs - 1],
						Base.kMatchMaxLen - lenRes);
			}
			_additionalOffset++;
		}


		void MovePos(UInt32 num)
		{
			if (num > 0)
			{
				_matchFinder.Skip(num);
				_additionalOffset += num;
			}
		}

		UInt32 GetRepLen1Price(Base.State state, UInt32 posState)
		{
			return _isRepG0[state.Index].GetPrice0() +
					_isRep0Long[(state.Index << Base.kNumPosStatesBitsMax) + posState].GetPrice0();
		}

		UInt32 GetPureRepPrice(UInt32 repIndex, Base.State state, UInt32 posState)
		{
			UInt32 price;
			if (repIndex == 0)
			{
				price = _isRepG0[state.Index].GetPrice0();
				price += _isRep0Long[(state.Index << Base.kNumPosStatesBitsMax) + posState].GetPrice1();
			}
			else
			{
				price = _isRepG0[state.Index].GetPrice1();
				if (repIndex == 1)
					price += _isRepG1[state.Index].GetPrice0();
				else
				{
					price += _isRepG1[state.Index].GetPrice1();
					price += _isRepG2[state.Index].GetPrice(repIndex - 2);
				}
			}
			return price;
		}

		UInt32 GetRepPrice(UInt32 repIndex, UInt32 len, Base.State state, UInt32 posState)
		{
			UInt32 price = _repMatchLenEncoder.GetPrice(len - Base.kMatchMinLen, posState);
			return price + GetPureRepPrice(repIndex, state, posState);
		}

		UInt32 GetPosLenPrice(UInt32 pos, UInt32 len, UInt32 posState)
		{
			UInt32 price;
			UInt32 lenToPosState = Base.GetLenToPosState(len);
			if (pos < Base.kNumFullDistances)
				price = _distancesPrices[(lenToPosState * Base.kNumFullDistances) + pos];
			else
				price = _posSlotPrices[(lenToPosState << Base.kNumPosSlotBits) + GetPosSlot2(pos)] +
					_alignPrices[pos & Base.kAlignMask];
			return price + _lenEncoder.GetPrice(len - Base.kMatchMinLen, posState);
		}

		UInt32 Backward(out UInt32 backRes, UInt32 cur)
		{
			_optimumEndIndex = cur;
			UInt32 posMem = _optimum[cur].PosPrev;
			UInt32 backMem = _optimum[cur].BackPrev;
			do
			{
				if (_optimum[cur].Prev1IsChar)
				{
					_optimum[posMem].MakeAsChar();
					_optimum[posMem].PosPrev = posMem - 1;
					if (_optimum[cur].Prev2)
					{
						_optimum[posMem - 1].Prev1IsChar = false;
						_optimum[posMem - 1].PosPrev = _optimum[cur].PosPrev2;
						_optimum[posMem - 1].BackPrev = _optimum[cur].BackPrev2;
					}
				}
				UInt32 posPrev = posMem;
				UInt32 backCur = backMem;

				backMem = _optimum[posPrev].BackPrev;
				posMem = _optimum[posPrev].PosPrev;

				_optimum[posPrev].BackPrev = backCur;
				_optimum[posPrev].PosPrev = cur;
				cur = posPrev;
			}
			while (cur > 0);
			backRes = _optimum[0].BackPrev;
			_optimumCurrentIndex = _optimum[0].PosPrev;
			return _optimumCurrentIndex;
		}

		UInt32[] reps = new UInt32[Base.kNumRepDistances];
		UInt32[] repLens = new UInt32[Base.kNumRepDistances];


		UInt32 GetOptimum(UInt32 position, out UInt32 backRes)
		{
			if (_optimumEndIndex != _optimumCurrentIndex)
			{
				UInt32 lenRes = _optimum[_optimumCurrentIndex].PosPrev - _optimumCurrentIndex;
				backRes = _optimum[_optimumCurrentIndex].BackPrev;
				_optimumCurrentIndex = _optimum[_optimumCurrentIndex].PosPrev;
				return lenRes;
			}
			_optimumCurrentIndex = _optimumEndIndex = 0;

			UInt32 lenMain, numDistancePairs;
			if (!_longestMatchWasFound)
			{
				ReadMatchDistances(out lenMain, out numDistancePairs);
			}
			else
			{
				lenMain = _longestMatchLength;
				numDistancePairs = _numDistancePairs;
				_longestMatchWasFound = false;
			}

			UInt32 numAvailableBytes = _matchFinder.GetNumAvailableBytes() + 1;
			if (numAvailableBytes < 2)
			{
				backRes = 0xFFFFFFFF;
				return 1;
			}
			if (numAvailableBytes > Base.kMatchMaxLen)
				numAvailableBytes = Base.kMatchMaxLen;

			UInt32 repMaxIndex = 0;
			UInt32 i;
			for (i = 0; i < Base.kNumRepDistances; i++)
			{
				reps[i] = _repDistances[i];
				repLens[i] = _matchFinder.GetMatchLen(0 - 1, reps[i], Base.kMatchMaxLen);
				if (repLens[i] > repLens[repMaxIndex])
					repMaxIndex = i;
			}
			if (repLens[repMaxIndex] >= _numFastBytes)
			{
				backRes = repMaxIndex;
				UInt32 lenRes = repLens[repMaxIndex];
				MovePos(lenRes - 1);
				return lenRes;
			}

			if (lenMain >= _numFastBytes)
			{
				backRes = _matchDistances[numDistancePairs - 1] + Base.kNumRepDistances;
				MovePos(lenMain - 1);
				return lenMain;
			}

			Byte currentByte = _matchFinder.GetIndexByte(0 - 1);
			Byte matchByte = _matchFinder.GetIndexByte((Int32)(0 - _repDistances[0] - 1 - 1));

			if (lenMain < 2 && currentByte != matchByte && repLens[repMaxIndex] < 2)
			{
				backRes = (UInt32)0xFFFFFFFF;
				return 1;
			}

			_optimum[0].State = _state;

			UInt32 posState = (position & _posStateMask);

			_optimum[1].Price = _isMatch[(_state.Index << Base.kNumPosStatesBitsMax) + posState].GetPrice0() +
					_literalEncoder.GetSubCoder(position, _previousByte).GetPrice(!_state.IsCharState(), matchByte, currentByte);
			_optimum[1].MakeAsChar();

			UInt32 matchPrice = _isMatch[(_state.Index << Base.kNumPosStatesBitsMax) + posState].GetPrice1();
			UInt32 repMatchPrice = matchPrice + _isRep[_state.Index].GetPrice1();

			if (matchByte == currentByte)
			{
				UInt32 shortRepPrice = repMatchPrice + GetRepLen1Price(_state, posState);
				if (shortRepPrice < _optimum[1].Price)
				{
					_optimum[1].Price = shortRepPrice;
					_optimum[1].MakeAsShortRep();
				}
			}

			UInt32 lenEnd = ((lenMain >= repLens[repMaxIndex]) ? lenMain : repLens[repMaxIndex]);

			if (lenEnd < 2)
			{
				backRes = _optimum[1].BackPrev;
				return 1;
			}

			_optimum[1].PosPrev = 0;

			_optimum[0].Backs0 = reps[0];
			_optimum[0].Backs1 = reps[1];
			_optimum[0].Backs2 = reps[2];
			_optimum[0].Backs3 = reps[3];

			UInt32 len = lenEnd;
			do
				_optimum[len--].Price = kIfinityPrice;
			while (len >= 2);

			for (i = 0; i < Base.kNumRepDistances; i++)
			{
				UInt32 repLen = repLens[i];
				if (repLen < 2)
					continue;
				UInt32 price = repMatchPrice + GetPureRepPrice(i, _state, posState);
				do
				{
					UInt32 curAndLenPrice = price + _repMatchLenEncoder.GetPrice(repLen - 2, posState);
					Optimal optimum = _optimum[repLen];
					if (curAndLenPrice < optimum.Price)
					{
						optimum.Price = curAndLenPrice;
						optimum.PosPrev = 0;
						optimum.BackPrev = i;
						optimum.Prev1IsChar = false;
					}
				}
				while (--repLen >= 2);
			}

			UInt32 normalMatchPrice = matchPrice + _isRep[_state.Index].GetPrice0();

			len = ((repLens[0] >= 2) ? repLens[0] + 1 : 2);
			if (len <= lenMain)
			{
				UInt32 offs = 0;
				while (len > _matchDistances[offs])
					offs += 2;
				for (; ; len++)
				{
					UInt32 distance = _matchDistances[offs + 1];
					UInt32 curAndLenPrice = normalMatchPrice + GetPosLenPrice(distance, len, posState);
					Optimal optimum = _optimum[len];
					if (curAndLenPrice < optimum.Price)
					{
						optimum.Price = curAndLenPrice;
						optimum.PosPrev = 0;
						optimum.BackPrev = distance + Base.kNumRepDistances;
						optimum.Prev1IsChar = false;
					}
					if (len == _matchDistances[offs])
					{
						offs += 2;
						if (offs == numDistancePairs)
							break;
					}
				}
			}

			UInt32 cur = 0;

			while (true)
			{
				cur++;
				if (cur == lenEnd)
					return Backward(out backRes, cur);
				UInt32 newLen;
				ReadMatchDistances(out newLen, out numDistancePairs);
				if (newLen >= _numFastBytes)
				{
					_numDistancePairs = numDistancePairs;
					_longestMatchLength = newLen;
					_longestMatchWasFound = true;
					return Backward(out backRes, cur);
				}
				position++;
				UInt32 posPrev = _optimum[cur].PosPrev;
				Base.State state;
				if (_optimum[cur].Prev1IsChar)
				{
					posPrev--;
					if (_optimum[cur].Prev2)
					{
						state = _optimum[_optimum[cur].PosPrev2].State;
						if (_optimum[cur].BackPrev2 < Base.kNumRepDistances)
							state.UpdateRep();
						else
							state.UpdateMatch();
					}
					else
						state = _optimum[posPrev].State;
					state.UpdateChar();
				}
				else
					state = _optimum[posPrev].State;
				if (posPrev == cur - 1)
				{
					if (_optimum[cur].IsShortRep())
						state.UpdateShortRep();
					else
						state.UpdateChar();
				}
				else
				{
					UInt32 pos;
					if (_optimum[cur].Prev1IsChar && _optimum[cur].Prev2)
					{
						posPrev = _optimum[cur].PosPrev2;
						pos = _optimum[cur].BackPrev2;
						state.UpdateRep();
					}
					else
					{
						pos = _optimum[cur].BackPrev;
						if (pos < Base.kNumRepDistances)
							state.UpdateRep();
						else
							state.UpdateMatch();
					}
					Optimal opt = _optimum[posPrev];
					if (pos < Base.kNumRepDistances)
					{
						if (pos == 0)
						{
							reps[0] = opt.Backs0;
							reps[1] = opt.Backs1;
							reps[2] = opt.Backs2;
							reps[3] = opt.Backs3;
						}
						else if (pos == 1)
						{
							reps[0] = opt.Backs1;
							reps[1] = opt.Backs0;
							reps[2] = opt.Backs2;
							reps[3] = opt.Backs3;
						}
						else if (pos == 2)
						{
							reps[0] = opt.Backs2;
							reps[1] = opt.Backs0;
							reps[2] = opt.Backs1;
							reps[3] = opt.Backs3;
						}
						else
						{
							reps[0] = opt.Backs3;
							reps[1] = opt.Backs0;
							reps[2] = opt.Backs1;
							reps[3] = opt.Backs2;
						}
					}
					else
					{
						reps[0] = (pos - Base.kNumRepDistances);
						reps[1] = opt.Backs0;
						reps[2] = opt.Backs1;
						reps[3] = opt.Backs2;
					}
				}
				_optimum[cur].State = state;
				_optimum[cur].Backs0 = reps[0];
				_optimum[cur].Backs1 = reps[1];
				_optimum[cur].Backs2 = reps[2];
				_optimum[cur].Backs3 = reps[3];
				UInt32 curPrice = _optimum[cur].Price;

				currentByte = _matchFinder.GetIndexByte(0 - 1);
				matchByte = _matchFinder.GetIndexByte((Int32)(0 - reps[0] - 1 - 1));

				posState = (position & _posStateMask);

				UInt32 curAnd1Price = curPrice +
					_isMatch[(state.Index << Base.kNumPosStatesBitsMax) + posState].GetPrice0() +
					_literalEncoder.GetSubCoder(position, _matchFinder.GetIndexByte(0 - 2)).
					GetPrice(!state.IsCharState(), matchByte, currentByte);

				Optimal nextOptimum = _optimum[cur + 1];

				bool nextIsChar = false;
				if (curAnd1Price < nextOptimum.Price)
				{
					nextOptimum.Price = curAnd1Price;
					nextOptimum.PosPrev = cur;
					nextOptimum.MakeAsChar();
					nextIsChar = true;
				}

				matchPrice = curPrice + _isMatch[(state.Index << Base.kNumPosStatesBitsMax) + posState].GetPrice1();
				repMatchPrice = matchPrice + _isRep[state.Index].GetPrice1();

				if (matchByte == currentByte &&
					!(nextOptimum.PosPrev < cur && nextOptimum.BackPrev == 0))
				{
					UInt32 shortRepPrice = repMatchPrice + GetRepLen1Price(state, posState);
					if (shortRepPrice <= nextOptimum.Price)
					{
						nextOptimum.Price = shortRepPrice;
						nextOptimum.PosPrev = cur;
						nextOptimum.MakeAsShortRep();
						nextIsChar = true;
					}
				}

				UInt32 numAvailableBytesFull = _matchFinder.GetNumAvailableBytes() + 1;
				numAvailableBytesFull = Math.Min(kNumOpts - 1 - cur, numAvailableBytesFull);
				numAvailableBytes = numAvailableBytesFull;

				if (numAvailableBytes < 2)
					continue;
				if (numAvailableBytes > _numFastBytes)
					numAvailableBytes = _numFastBytes;
				if (!nextIsChar && matchByte != currentByte)
				{
					// try Literal + rep0
					UInt32 t = Math.Min(numAvailableBytesFull - 1, _numFastBytes);
					UInt32 lenTest2 = _matchFinder.GetMatchLen(0, reps[0], t);
					if (lenTest2 >= 2)
					{
						Base.State state2 = state;
						state2.UpdateChar();
						UInt32 posStateNext = (position + 1) & _posStateMask;
						UInt32 nextRepMatchPrice = curAnd1Price +
							_isMatch[(state2.Index << Base.kNumPosStatesBitsMax) + posStateNext].GetPrice1() +
							_isRep[state2.Index].GetPrice1();
						{
							UInt32 offset = cur + 1 + lenTest2;
							while (lenEnd < offset)
								_optimum[++lenEnd].Price = kIfinityPrice;
							UInt32 curAndLenPrice = nextRepMatchPrice + GetRepPrice(
								0, lenTest2, state2, posStateNext);
							Optimal optimum = _optimum[offset];
							if (curAndLenPrice < optimum.Price)
							{
								optimum.Price = curAndLenPrice;
								optimum.PosPrev = cur + 1;
								optimum.BackPrev = 0;
								optimum.Prev1IsChar = true;
								optimum.Prev2 = false;
							}
						}
					}
				}

				UInt32 startLen = 2; // speed optimization

				for (UInt32 repIndex = 0; repIndex < Base.kNumRepDistances; repIndex++)
				{
					UInt32 lenTest = _matchFinder.GetMatchLen(0 - 1, reps[repIndex], numAvailableBytes);
					if (lenTest < 2)
						continue;
					UInt32 lenTestTemp = lenTest;
					do
					{
						while (lenEnd < cur + lenTest)
							_optimum[++lenEnd].Price = kIfinityPrice;
						UInt32 curAndLenPrice = repMatchPrice + GetRepPrice(repIndex, lenTest, state, posState);
						Optimal optimum = _optimum[cur + lenTest];
						if (curAndLenPrice < optimum.Price)
						{
							optimum.Price = curAndLenPrice;
							optimum.PosPrev = cur;
							optimum.BackPrev = repIndex;
							optimum.Prev1IsChar = false;
						}
					}
					while (--lenTest >= 2);
					lenTest = lenTestTemp;

					if (repIndex == 0)
						startLen = lenTest + 1;

					// if (_maxMode)
					if (lenTest < numAvailableBytesFull)
					{
						UInt32 t = Math.Min(numAvailableBytesFull - 1 - lenTest, _numFastBytes);
						UInt32 lenTest2 = _matchFinder.GetMatchLen((Int32)lenTest, reps[repIndex], t);
						if (lenTest2 >= 2)
						{
							Base.State state2 = state;
							state2.UpdateRep();
							UInt32 posStateNext = (position + lenTest) & _posStateMask;
							UInt32 curAndLenCharPrice =
									repMatchPrice + GetRepPrice(repIndex, lenTest, state, posState) +
									_isMatch[(state2.Index << Base.kNumPosStatesBitsMax) + posStateNext].GetPrice0() +
									_literalEncoder.GetSubCoder(position + lenTest,
									_matchFinder.GetIndexByte((Int32)lenTest - 1 - 1)).GetPrice(true,
									_matchFinder.GetIndexByte((Int32)((Int32)lenTest - 1 - (Int32)(reps[repIndex] + 1))),
									_matchFinder.GetIndexByte((Int32)lenTest - 1));
							state2.UpdateChar();
							posStateNext = (position + lenTest + 1) & _posStateMask;
							UInt32 nextMatchPrice = curAndLenCharPrice + _isMatch[(state2.Index << Base.kNumPosStatesBitsMax) + posStateNext].GetPrice1();
							UInt32 nextRepMatchPrice = nextMatchPrice + _isRep[state2.Index].GetPrice1();

							// for(; lenTest2 >= 2; lenTest2--)
							{
								UInt32 offset = lenTest + 1 + lenTest2;
								while (lenEnd < cur + offset)
									_optimum[++lenEnd].Price = kIfinityPrice;
								UInt32 curAndLenPrice = nextRepMatchPrice + GetRepPrice(0, lenTest2, state2, posStateNext);
								Optimal optimum = _optimum[cur + offset];
								if (curAndLenPrice < optimum.Price)
								{
									optimum.Price = curAndLenPrice;
									optimum.PosPrev = cur + lenTest + 1;
									optimum.BackPrev = 0;
									optimum.Prev1IsChar = true;
									optimum.Prev2 = true;
									optimum.PosPrev2 = cur;
									optimum.BackPrev2 = repIndex;
								}
							}
						}
					}
				}

				if (newLen > numAvailableBytes)
				{
					newLen = numAvailableBytes;
					for (numDistancePairs = 0; newLen > _matchDistances[numDistancePairs]; numDistancePairs += 2) ;
					_matchDistances[numDistancePairs] = newLen;
					numDistancePairs += 2;
				}
				if (newLen >= startLen)
				{
					normalMatchPrice = matchPrice + _isRep[state.Index].GetPrice0();
					while (lenEnd < cur + newLen)
						_optimum[++lenEnd].Price = kIfinityPrice;

					UInt32 offs = 0;
					while (startLen > _matchDistances[offs])
						offs += 2;

					for (UInt32 lenTest = startLen; ; lenTest++)
					{
						UInt32 curBack = _matchDistances[offs + 1];
						UInt32 curAndLenPrice = normalMatchPrice + GetPosLenPrice(curBack, lenTest, posState);
						Optimal optimum = _optimum[cur + lenTest];
						if (curAndLenPrice < optimum.Price)
						{
							optimum.Price = curAndLenPrice;
							optimum.PosPrev = cur;
							optimum.BackPrev = curBack + Base.kNumRepDistances;
							optimum.Prev1IsChar = false;
						}

						if (lenTest == _matchDistances[offs])
						{
							if (lenTest < numAvailableBytesFull)
							{
								UInt32 t = Math.Min(numAvailableBytesFull - 1 - lenTest, _numFastBytes);
								UInt32 lenTest2 = _matchFinder.GetMatchLen((Int32)lenTest, curBack, t);
								if (lenTest2 >= 2)
								{
									Base.State state2 = state;
									state2.UpdateMatch();
									UInt32 posStateNext = (position + lenTest) & _posStateMask;
									UInt32 curAndLenCharPrice = curAndLenPrice +
										_isMatch[(state2.Index << Base.kNumPosStatesBitsMax) + posStateNext].GetPrice0() +
										_literalEncoder.GetSubCoder(position + lenTest,
										_matchFinder.GetIndexByte((Int32)lenTest - 1 - 1)).
										GetPrice(true,
										_matchFinder.GetIndexByte((Int32)lenTest - (Int32)(curBack + 1) - 1),
										_matchFinder.GetIndexByte((Int32)lenTest - 1));
									state2.UpdateChar();
									posStateNext = (position + lenTest + 1) & _posStateMask;
									UInt32 nextMatchPrice = curAndLenCharPrice + _isMatch[(state2.Index << Base.kNumPosStatesBitsMax) + posStateNext].GetPrice1();
									UInt32 nextRepMatchPrice = nextMatchPrice + _isRep[state2.Index].GetPrice1();

									UInt32 offset = lenTest + 1 + lenTest2;
									while (lenEnd < cur + offset)
										_optimum[++lenEnd].Price = kIfinityPrice;
									curAndLenPrice = nextRepMatchPrice + GetRepPrice(0, lenTest2, state2, posStateNext);
									optimum = _optimum[cur + offset];
									if (curAndLenPrice < optimum.Price)
									{
										optimum.Price = curAndLenPrice;
										optimum.PosPrev = cur + lenTest + 1;
										optimum.BackPrev = 0;
										optimum.Prev1IsChar = true;
										optimum.Prev2 = true;
										optimum.PosPrev2 = cur;
										optimum.BackPrev2 = curBack + Base.kNumRepDistances;
									}
								}
							}
							offs += 2;
							if (offs == numDistancePairs)
								break;
						}
					}
				}
			}
		}

		bool ChangePair(UInt32 smallDist, UInt32 bigDist)
		{
			const int kDif = 7;
			return (smallDist < ((UInt32)(1) << (32 - kDif)) && bigDist >= (smallDist << kDif));
		}

		void WriteEndMarker(UInt32 posState)
		{
			if (!_writeEndMark)
				return;

			_isMatch[(_state.Index << Base.kNumPosStatesBitsMax) + posState].Encode(_rangeEncoder, 1);
			_isRep[_state.Index].Encode(_rangeEncoder, 0);
			_state.UpdateMatch();
			UInt32 len = Base.kMatchMinLen;
			_lenEncoder.Encode(_rangeEncoder, len - Base.kMatchMinLen, posState);
			UInt32 posSlot = (1 << Base.kNumPosSlotBits) - 1;
			UInt32 lenToPosState = Base.GetLenToPosState(len);
			_posSlotEncoder[lenToPosState].Encode(_rangeEncoder, posSlot);
			int footerBits = 30;
			UInt32 posReduced = (((UInt32)1) << footerBits) - 1;
			_rangeEncoder.EncodeDirectBits(posReduced >> Base.kNumAlignBits, footerBits - Base.kNumAlignBits);
			_posAlignEncoder.ReverseEncode(_rangeEncoder, posReduced & Base.kAlignMask);
		}

		void Flush(UInt32 nowPos)
		{
			ReleaseMFStream();
			WriteEndMarker(nowPos & _posStateMask);
			_rangeEncoder.FlushData();
			_rangeEncoder.FlushStream();
		}

		public void CodeOneBlock(out Int64 inSize, out Int64 outSize, out bool finished)
		{
			inSize = 0;
			outSize = 0;
			finished = true;

			if (_inStream != null)
			{
				_matchFinder.SetStream(_inStream);
				_matchFinder.Init();
				_needReleaseMFStream = true;
				_inStream = null;
				if (_trainSize > 0)
					_matchFinder.Skip(_trainSize);
			}

			if (_finished)
				return;
			_finished = true;


			Int64 progressPosValuePrev = nowPos64;
			if (nowPos64 == 0)
			{
				if (_matchFinder.GetNumAvailableBytes() == 0)
				{
					Flush((UInt32)nowPos64);
					return;
				}
				UInt32 len, numDistancePairs; // it's not used
				ReadMatchDistances(out len, out numDistancePairs);
				UInt32 posState = (UInt32)(nowPos64) & _posStateMask;
				_isMatch[(_state.Index << Base.kNumPosStatesBitsMax) + posState].Encode(_rangeEncoder, 0);
				_state.UpdateChar();
				Byte curByte = _matchFinder.GetIndexByte((Int32)(0 - _additionalOffset));
				_literalEncoder.GetSubCoder((UInt32)(nowPos64), _previousByte).Encode(_rangeEncoder, curByte);
				_previousByte = curByte;
				_additionalOffset--;
				nowPos64++;
			}
			if (_matchFinder.GetNumAvailableBytes() == 0)
			{
				Flush((UInt32)nowPos64);
				return;
			}
			while (true)
			{
				UInt32 pos;
				UInt32 len = GetOptimum((UInt32)nowPos64, out pos);

				UInt32 posState = ((UInt32)nowPos64) & _posStateMask;
				UInt32 complexState = (_state.Index << Base.kNumPosStatesBitsMax) + posState;
				if (len == 1 && pos == 0xFFFFFFFF)
				{
					_isMatch[complexState].Encode(_rangeEncoder, 0);
					Byte curByte = _matchFinder.GetIndexByte((Int32)(0 - _additionalOffset));
					LiteralEncoder.Encoder2 subCoder = _literalEncoder.GetSubCoder((UInt32)nowPos64, _previousByte);
					if (!_state.IsCharState())
					{
						Byte matchByte = _matchFinder.GetIndexByte((Int32)(0 - _repDistances[0] - 1 - _additionalOffset));
						subCoder.EncodeMatched(_rangeEncoder, matchByte, curByte);
					}
					else
						subCoder.Encode(_rangeEncoder, curByte);
					_previousByte = curByte;
					_state.UpdateChar();
				}
				else
				{
					_isMatch[complexState].Encode(_rangeEncoder, 1);
					if (pos < Base.kNumRepDistances)
					{
						_isRep[_state.Index].Encode(_rangeEncoder, 1);
						if (pos == 0)
						{
							_isRepG0[_state.Index].Encode(_rangeEncoder, 0);
							if (len == 1)
								_isRep0Long[complexState].Encode(_rangeEncoder, 0);
							else
								_isRep0Long[complexState].Encode(_rangeEncoder, 1);
						}
						else
						{
							_isRepG0[_state.Index].Encode(_rangeEncoder, 1);
							if (pos == 1)
								_isRepG1[_state.Index].Encode(_rangeEncoder, 0);
							else
							{
								_isRepG1[_state.Index].Encode(_rangeEncoder, 1);
								_isRepG2[_state.Index].Encode(_rangeEncoder, pos - 2);
							}
						}
						if (len == 1)
							_state.UpdateShortRep();
						else
						{
							_repMatchLenEncoder.Encode(_rangeEncoder, len - Base.kMatchMinLen, posState);
							_state.UpdateRep();
						}
						UInt32 distance = _repDistances[pos];
						if (pos != 0)
						{
							for (UInt32 i = pos; i >= 1; i--)
								_repDistances[i] = _repDistances[i - 1];
							_repDistances[0] = distance;
						}
					}
					else
					{
						_isRep[_state.Index].Encode(_rangeEncoder, 0);
						_state.UpdateMatch();
						_lenEncoder.Encode(_rangeEncoder, len - Base.kMatchMinLen, posState);
						pos -= Base.kNumRepDistances;
						UInt32 posSlot = GetPosSlot(pos);
						UInt32 lenToPosState = Base.GetLenToPosState(len);
						_posSlotEncoder[lenToPosState].Encode(_rangeEncoder, posSlot);

						if (posSlot >= Base.kStartPosModelIndex)
						{
							int footerBits = (int)((posSlot >> 1) - 1);
							UInt32 baseVal = ((2 | (posSlot & 1)) << footerBits);
							UInt32 posReduced = pos - baseVal;

							if (posSlot < Base.kEndPosModelIndex)
								RangeCoder.BitTreeEncoder.ReverseEncode(_posEncoders,
										baseVal - posSlot - 1, _rangeEncoder, footerBits, posReduced);
							else
							{
								_rangeEncoder.EncodeDirectBits(posReduced >> Base.kNumAlignBits, footerBits - Base.kNumAlignBits);
								_posAlignEncoder.ReverseEncode(_rangeEncoder, posReduced & Base.kAlignMask);
								_alignPriceCount++;
							}
						}
						UInt32 distance = pos;
						for (UInt32 i = Base.kNumRepDistances - 1; i >= 1; i--)
							_repDistances[i] = _repDistances[i - 1];
						_repDistances[0] = distance;
						_matchPriceCount++;
					}
					_previousByte = _matchFinder.GetIndexByte((Int32)(len - 1 - _additionalOffset));
				}
				_additionalOffset -= len;
				nowPos64 += len;
				if (_additionalOffset == 0)
				{
					// if (!_fastMode)
					if (_matchPriceCount >= (1 << 7))
						FillDistancesPrices();
					if (_alignPriceCount >= Base.kAlignTableSize)
						FillAlignPrices();
					inSize = nowPos64;
					outSize = _rangeEncoder.GetProcessedSizeAdd();
					if (_matchFinder.GetNumAvailableBytes() == 0)
					{
						Flush((UInt32)nowPos64);
						return;
					}

					if (nowPos64 - progressPosValuePrev >= (1 << 12))
					{
						_finished = false;
						finished = false;
						return;
					}
				}
			}
		}

		void ReleaseMFStream()
		{
			if (_matchFinder != null && _needReleaseMFStream)
			{
				_matchFinder.ReleaseStream();
				_needReleaseMFStream = false;
			}
		}

		void SetOutStream(System.IO.Stream outStream) { _rangeEncoder.SetStream(outStream); }
		void ReleaseOutStream() { _rangeEncoder.ReleaseStream(); }

		void ReleaseStreams()
		{
			ReleaseMFStream();
			ReleaseOutStream();
		}

		void SetStreams(System.IO.Stream inStream, System.IO.Stream outStream,
				Int64 inSize, Int64 outSize)
		{
			_inStream = inStream;
			_finished = false;
			Create();
			SetOutStream(outStream);
			Init();

			// if (!_fastMode)
			{
				FillDistancesPrices();
				FillAlignPrices();
			}

			_lenEncoder.SetTableSize(_numFastBytes + 1 - Base.kMatchMinLen);
			_lenEncoder.UpdateTables((UInt32)1 << _posStateBits);
			_repMatchLenEncoder.SetTableSize(_numFastBytes + 1 - Base.kMatchMinLen);
			_repMatchLenEncoder.UpdateTables((UInt32)1 << _posStateBits);

			nowPos64 = 0;
		}


		public void Code(System.IO.Stream inStream, System.IO.Stream outStream,
			Int64 inSize, Int64 outSize, ICodeProgress progress)
		{
			_needReleaseMFStream = false;
			try
			{
				SetStreams(inStream, outStream, inSize, outSize);
				while (true)
				{
					Int64 processedInSize;
					Int64 processedOutSize;
					bool finished;
					CodeOneBlock(out processedInSize, out processedOutSize, out finished);
					if (finished)
						return;
					if (progress != null)
					{
						progress.SetProgress(processedInSize, processedOutSize);
					}
				}
			}
			finally
			{
				ReleaseStreams();
			}
		}

		const int kPropSize = 5;
		Byte[] properties = new Byte[kPropSize];

		public void WriteCoderProperties(System.IO.Stream outStream)
		{
			properties[0] = (Byte)((_posStateBits * 5 + _numLiteralPosStateBits) * 9 + _numLiteralContextBits);
			for (int i = 0; i < 4; i++)
				properties[1 + i] = (Byte)((_dictionarySize >> (8 * i)) & 0xFF);
			outStream.Write(properties, 0, kPropSize);
		}

		UInt32[] tempPrices = new UInt32[Base.kNumFullDistances];
		UInt32 _matchPriceCount;

		void FillDistancesPrices()
		{
			for (UInt32 i = Base.kStartPosModelIndex; i < Base.kNumFullDistances; i++)
			{
				UInt32 posSlot = GetPosSlot(i);
				int footerBits = (int)((posSlot >> 1) - 1);
				UInt32 baseVal = ((2 | (posSlot & 1)) << footerBits);
				tempPrices[i] = BitTreeEncoder.ReverseGetPrice(_posEncoders,
					baseVal - posSlot - 1, footerBits, i - baseVal);
			}

			for (UInt32 lenToPosState = 0; lenToPosState < Base.kNumLenToPosStates; lenToPosState++)
			{
				UInt32 posSlot;
				RangeCoder.BitTreeEncoder encoder = _posSlotEncoder[lenToPosState];

				UInt32 st = (lenToPosState << Base.kNumPosSlotBits);
				for (posSlot = 0; posSlot < _distTableSize; posSlot++)
					_posSlotPrices[st + posSlot] = encoder.GetPrice(posSlot);
				for (posSlot = Base.kEndPosModelIndex; posSlot < _distTableSize; posSlot++)
					_posSlotPrices[st + posSlot] += ((((posSlot >> 1) - 1) - Base.kNumAlignBits) << RangeCoder.BitEncoder.kNumBitPriceShiftBits);

				UInt32 st2 = lenToPosState * Base.kNumFullDistances;
				UInt32 i;
				for (i = 0; i < Base.kStartPosModelIndex; i++)
					_distancesPrices[st2 + i] = _posSlotPrices[st + i];
				for (; i < Base.kNumFullDistances; i++)
					_distancesPrices[st2 + i] = _posSlotPrices[st + GetPosSlot(i)] + tempPrices[i];
			}
			_matchPriceCount = 0;
		}

		void FillAlignPrices()
		{
			for (UInt32 i = 0; i < Base.kAlignTableSize; i++)
				_alignPrices[i] = _posAlignEncoder.ReverseGetPrice(i);
			_alignPriceCount = 0;
		}


		static string[] kMatchFinderIDs =
		{
			"BT2",
			"BT4",
		};

		static int FindMatchFinder(string s)
		{
			for (int m = 0; m < kMatchFinderIDs.Length; m++)
				if (s == kMatchFinderIDs[m])
					return m;
			return -1;
		}

		public void SetCoderProperties(CoderPropID[] propIDs, object[] properties)
		{
			for (UInt32 i = 0; i < properties.Length; i++)
			{
				object prop = properties[i];
				switch (propIDs[i])
				{
					case CoderPropID.NumFastBytes:
						{
							if (!(prop is Int32))
								throw new InvalidParamException();
							Int32 numFastBytes = (Int32)prop;
							if (numFastBytes < 5 || numFastBytes > Base.kMatchMaxLen)
								throw new InvalidParamException();
							_numFastBytes = (UInt32)numFastBytes;
							break;
						}
					case CoderPropID.Algorithm:
						{
							/*
							if (!(prop is Int32))
								throw new InvalidParamException();
							Int32 maximize = (Int32)prop;
							_fastMode = (maximize == 0);
							_maxMode = (maximize >= 2);
							*/
							break;
						}
					case CoderPropID.MatchFinder:
						{
							if (!(prop is String))
								throw new InvalidParamException();
							EMatchFinderType matchFinderIndexPrev = _matchFinderType;
							int m = FindMatchFinder(((string)prop).ToUpper());
							if (m < 0)
								throw new InvalidParamException();
							_matchFinderType = (EMatchFinderType)m;
							if (_matchFinder != null && matchFinderIndexPrev != _matchFinderType)
							{
								_dictionarySizePrev = 0xFFFFFFFF;
								_matchFinder = null;
							}
							break;
						}
					case CoderPropID.DictionarySize:
						{
							const int kDicLogSizeMaxCompress = 30;
							if (!(prop is Int32))
								throw new InvalidParamException(); ;
							Int32 dictionarySize = (Int32)prop;
							if (dictionarySize < (UInt32)(1 << Base.kDicLogSizeMin) ||
								dictionarySize > (UInt32)(1 << kDicLogSizeMaxCompress))
								throw new InvalidParamException();
							_dictionarySize = (UInt32)dictionarySize;
							int dicLogSize;
							for (dicLogSize = 0; dicLogSize < (UInt32)kDicLogSizeMaxCompress; dicLogSize++)
								if (dictionarySize <= ((UInt32)(1) << dicLogSize))
									break;
							_distTableSize = (UInt32)dicLogSize * 2;
							break;
						}
					case CoderPropID.PosStateBits:
						{
							if (!(prop is Int32))
								throw new InvalidParamException();
							Int32 v = (Int32)prop;
							if (v < 0 || v > (UInt32)Base.kNumPosStatesBitsEncodingMax)
								throw new InvalidParamException();
							_posStateBits = (int)v;
							_posStateMask = (((UInt32)1) << (int)_posStateBits) - 1;
							break;
						}
					case CoderPropID.LitPosBits:
						{
							if (!(prop is Int32))
								throw new InvalidParamException();
							Int32 v = (Int32)prop;
							if (v < 0 || v > (UInt32)Base.kNumLitPosStatesBitsEncodingMax)
								throw new InvalidParamException();
							_numLiteralPosStateBits = (int)v;
							break;
						}
					case CoderPropID.LitContextBits:
						{
							if (!(prop is Int32))
								throw new InvalidParamException();
							Int32 v = (Int32)prop;
							if (v < 0 || v > (UInt32)Base.kNumLitContextBitsMax)
								throw new InvalidParamException(); ;
							_numLiteralContextBits = (int)v;
							break;
						}
					case CoderPropID.EndMarker:
						{
							if (!(prop is Boolean))
								throw new InvalidParamException();
							SetWriteEndMarkerMode((Boolean)prop);
							break;
						}
					default:
						throw new InvalidParamException();
				}
			}
		}

		uint _trainSize = 0;
		public void SetTrainSize(uint trainSize)
		{
			_trainSize = trainSize;
		}

	}
}

namespace SevenZip.Compression.LZMA
{
	public class LZMAAPI
	{
		private static readonly Int32 c_propertiesLength = 5;
		private static readonly Int32 c_outputSizeLength = 8;

		public static void Decompress(string inFilePath, string outFilePath)
		{
			using (var inStream = new FileStream(inFilePath, FileMode.Open, FileAccess.Read))
			using (var outStream = new FileStream(outFilePath, FileMode.Create, FileAccess.Write))
			{
				byte[] properties = new byte[c_propertiesLength];
				if (inStream.Read(properties, (Int32)0, c_propertiesLength) != c_propertiesLength)
				{
					throw new Exception("Input file is too short");
				}

				var decoder = new Compression.LZMA.Decoder();
				decoder.SetDecoderProperties(properties);
				long outSize = 0;
				for (Int32 i = 0; i < c_outputSizeLength; i++)
				{
					int size = inStream.ReadByte();
					if (size < 0)
					{
						throw new Exception("Input file is too short");
					}
					outSize |= ((long)(byte)size) << (8 * i);
				}
				long compressedSize = inStream.Length - inStream.Position;
				decoder.Code(inStream, outStream, compressedSize, outSize, null);
			}
		}

		public static void Compress(string inFilePath, string outFilePath, Int32 dictionarySize = 1 << 25, Int32 numFastBytes = 273)
		{
			using (var inStream = new FileStream(inFilePath, FileMode.Open, FileAccess.Read))
			using (var outStream = new FileStream(outFilePath, FileMode.Create, FileAccess.Write))
			{
				// State bits for LZMA
				Int32 posStateBits = 2;
				// normal file
				Int32 litContextBits = 3;
				// 64Bit system
				Int32 litPosBits = 0;
				// LZMA algorithm
				Int32 algorithm = 2;
				// End marker
				bool eos = false;
				// Match finder for LZMA
				string mf = "bt4";
				CoderPropID[] propIDs =
				{
					CoderPropID.DictionarySize,
					CoderPropID.PosStateBits,
					CoderPropID.LitContextBits,
					CoderPropID.LitPosBits,
					CoderPropID.Algorithm,
					CoderPropID.NumFastBytes,
					CoderPropID.MatchFinder,
					CoderPropID.EndMarker
			};
				object[] properties =
				{
					(Int32)(dictionarySize),
					(Int32)(posStateBits),
					(Int32)(litContextBits),
					(Int32)(litPosBits),
					(Int32)(algorithm),
					(Int32)(numFastBytes),
					mf,
					eos
			};
				Compression.LZMA.Encoder encoder = new Compression.LZMA.Encoder();
				encoder.SetCoderProperties(propIDs, properties);
				encoder.WriteCoderProperties(outStream);
				Int64 fileSize;

				fileSize = inStream.Length;
				for (Int32 i = 0; i < c_outputSizeLength; i++)
				{
					outStream.WriteByte((byte)(fileSize >> (8 * i)));
				}

				encoder.Code(inStream, outStream, -1, -1, null);
			}
		}
	}
}
"@
Add-Type -TypeDefinition $LZMA_CS_2951093068 -Language CSharp -IgnoreWarnings

function Compress-LZMA {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string] $InputPath,

        [Parameter(Mandatory=$true)]
        [string] $OutputPath
    )
    [SevenZip.Compression.LZMA.LZMAAPI]::Compress($InputPath, $OutputPath)
}

function Decompress-LZMA {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string] $InputPath,

        [Parameter(Mandatory=$true)]
        [string] $OutputPath
    )
    [SevenZip.Compression.LZMA.LZMAAPI]::Decompress($InputPath, $OutputPath)
}

#------------------------------------------------------------ Common Modules  -------------------------------------------

#---------------------------------------------------------------- Hash  -------------------------------------------------
function Get-StringHashForAlgorithm
{
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [AllowNull()]
		[AllowEmptyString()]
        [String] $InputString,

        [Parameter(Mandatory)]
        [String] $Algorithm
    )

    $StringAsStream = [System.IO.MemoryStream]::new()
    $Writer = [System.IO.StreamWriter]::new($StringAsStream)
    $Writer.write($InputString.TrimEnd())
    $Writer.Flush()
    $StringAsStream.Position = 0
    return Get-FileHash -Algorithm $Algorithm -InputStream $StringAsStream | Select-Object -ExpandProperty Hash
}

function Get-StringHashSHA1
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [AllowNull()]
		[AllowEmptyString()]
        [String] $InputString
    )

    return Get-StringHashForAlgorithm $InputString 'SHA1'
}

function Get-StringHashSHA256
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [AllowNull()]
		[AllowEmptyString()]
        [String] $InputString
    )

    return Get-StringHashForAlgorithm $InputString 'SHA256'
}

function Get-FileHashSHA256String
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $File
    )
    return Get-FileHash $File -Algorithm SHA256 | Select-Object -ExpandProperty Hash
}



#-------------------------------------------------------------- Hash End  ----------------------------------------------
#------------------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------ VerifyScripts  --------------------------------------------
class VerifyScriptException : Exception
{}

class VerifyScriptSignatureMismatchException : VerifyScriptException
{
    [String] $FileSignatureStatus

    [AllowEmptyString()]
    [String] $FileSignatureThumbprint

    [String] ToString()
    {
        return "Failed to verify script signature. Signature status: $($this.FileSignatureStatus); Calculated thumbprint: $($this.FileSignatureThumbprint)"
    }
}

class VerifyScriptHashMismatchException : VerifyScriptException
{
    [String] $CalculatedHash

    [String] ToString()
    {
        return "Failed to verify script hash. Calculated hash: $($this.CalculatedHash)"
    }
}

class VerifyScriptGeneralErrorException : VerifyScriptException
{
    [Exception] $Exception

    [String] ToString()
    {
        return "Failed with general error: $($this.Exception.ToString())"
    }
}

function Get-ContentNoSignature
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [String] $Path
    )

    $Content = Get-Content $Path
    $SignatureMatch = $Content | Select-String "SIG # Begin signature block"
    if ($null -eq $SignatureMatch)
    {
        return $Content | Out-String
    }
    $End = $SignatureMatch.LineNumber - 2
    return $Content[0 .. $End] | Out-String
}

function Get-FileHashSHA256
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String] $Path
    )
    return (Get-FileHash $Path -Algorithm SHA256).Hash
}

function Get-FileHashSHA256NoSignature
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String] $Path
    )
    return $Path | Get-ContentNoSignature | Get-StringHashSHA256
}

function Use-VerifiedScript
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $ScriptPath,

        [Parameter(Mandatory = $true)]
        [String[]] $ValidSignatureThumbprints,

        [Parameter(Mandatory = $true)]
        [String] $ExpectedFileHash,

        [Parameter(Mandatory = $true)]
        [ScriptBlock] $Logic,

        [String[]] $LogicArguments
    )

    $FunctionsfileStreamForLock = $null
    try
    {
        $FunctionsfileStreamForLock = [System.IO.File]::Open($ScriptPath, 'Open', 'Read', 'Read')

        Test-VerifiedFile $ScriptPath $ValidSignatureThumbprints $ExpectedFileHash -IgnoreSignatureInFileContent

        [Array] $LogicArgs = @($ScriptPath) + $LogicArguments | Where-Object { $_ }
        return Invoke-Command $Logic -ArgumentList $LogicArgs
    }
    catch [VerifyScriptException]
    {
        throw $_
    }
    catch
    {
        throw New-Object VerifyScriptGeneralErrorException -Property @{
            Exception = $_.Exception
        }
    }
    finally
    {
        if ($null -ne $FunctionsfileStreamForLock)
        {
            $FunctionsfileStreamForLock.Dispose()
        }
    }
}

function Get-VerifiedImportScript
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String] $ScriptPath,

        [Parameter(Mandatory)]
        [String[]] $ValidSignatureThumbprints,

        [Parameter(Mandatory)]
        [String] $ExpectedFileHash,

        [Switch] $Dev
    )

    if ($Dev)
    {
        return [ScriptBlock]::Create((Get-Content $ScriptPath | Out-String))
    }

    return Use-VerifiedScript $ScriptPath $ValidSignatureThumbprints $ExpectedFileHash {
        param (
            [Parameter(Mandatory = $true)]
            [String] $ScriptPath
        )

        return [ScriptBlock]::Create((Get-Content $ScriptPath | Out-String))
    }
}

function Start-VerifiedScript
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $ScriptPath,

        [Parameter(Mandatory = $true)]
        [String[]] $ValidSignatureThumbprints,

        [Parameter(Mandatory = $true)]
        [String] $ExpectedFileHash,

        [AllowNull()]
        [AllowEmptyCollection()]
        [String[]] $ScriptArguments,

        [Switch] $Dev
    )

    $Logic = {
        param (
            [Parameter(Mandatory = $true)]
            [String] $ScriptPath
        )

        [Array] $ArgList = @(@('-NoProfile', '-NonInteractive', "& '$ScriptPath'") + $ScriptArguments | Where-Object { $_ })
        Start-Process PowerShell -ArgumentList $ArgList -WindowStyle Hidden
    }

    if ($Dev)
    {
        Invoke-Command $Logic -ArgumentList $ScriptPath
        return
    }

    Use-VerifiedScript $ScriptPath $ValidSignatureThumbprints $ExpectedFileHash $Logic $ScriptArguments
}

function Test-FileHash
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String] $FilePath,

        [Parameter(Mandatory)]
        [String] $ExpectedFileHash,

        [Parameter()]
        [Switch] $IgnoreSignatureInFileContent
    )

    if ($IgnoreSignatureInFileContent)
    {
        $FileHash = Get-FileHashSHA256NoSignature $FilePath
    }
    else
    {
        $FileHash = Get-FileHashSHA256 $FilePath
    }

    if ($FileHash -ne $ExpectedFileHash)
    {
        throw New-Object VerifyScriptHashMismatchException -Property @{
            CalculatedHash = $FileHash
        }
    }
}

function Test-VerifiedFile
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String] $FilePath,

        [Parameter(Mandatory)]
        [String[]] $ValidSignatureThumbprints,

        [Parameter(Mandatory)]
        [String] $ExpectedFileHash,

        [Switch] $IgnoreSignatureInFileContent
    )

    $FileSignature = Get-AuthenticodeSignature -FilePath $FilePath

    if ($FileSignature.Status -ne "Valid" -or !($ValidSignatureThumbprints.Contains($FileSignature.SignerCertificate.Thumbprint)))
    {
        throw New-Object VerifyScriptSignatureMismatchException -Property @{
            FileSignatureStatus        = $FileSignature.Status
            FileSignatureThumbprint    = $FileSignature.SignerCertificate.Thumbprint
        }
    }

    Test-FileHash $FilePath $ExpectedFileHash -IgnoreSignatureInFileContent:$IgnoreSignatureInFileContent
}

#--------------------------------------------------------- VerifyScripts End  -------------------------------------------

#------------------------------------------------------------- Exceptions  ----------------------------------------------
function Get-SlimStacktrace
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord] $Exception
    )

    $SlimStacktrace = "Stacktrace:`n"
    $StackTraces = $Exception.ScriptStackTrace -split "`n"
    foreach ($StackTrace in $StackTraces)
    {
        if ($StackTrace -match '.*\\(.*): line ([\d]+)$')
        {
            $ScriptName = $matches[1]
            $ScriptLine = $matches[2]
            $SlimStacktrace += "$ScriptName : $ScriptLine`n"
        }
    }

    return $SlimStacktrace
}

function Get-SlimException
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord] $Exception,

        # Choose whether to add the exception message or not
        # Use with caution, it might contain PII.
        [switch] $WithMessage
    )

    return New-Object PSObject -Property @{
        ErrId        = $Exception.FullyQualifiedErrorId
        CategoryInfo = @{
            Category = $Exception.CategoryInfo.Category
            Activity = $Exception.CategoryInfo.Activity
            Reason   = $Exception.CategoryInfo.Reason
        }
        Line         = $Exception.InvocationInfo.Line
        StackTrace   = Get-SlimStacktrace $Exception
        Message      = if ($WithMessage) { $Exception.Exception.ToString() } else { $null }
    }
}

#----------------------------------------------------------- Exceptions End  --------------------------------------------

function Rename-ToolFromPs1ToExe
{
    [CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string] $Ps1FullPath,

		[Parameter(Mandatory = $true)]
		[string] $ExeFullPath,

        [parameter(Mandatory = $false)]
        [switch] $DeleteIfExists
	)
    if ((!$DeleteIfExists) -and (Test-Path $ExeFullPath))
    {
        return
    }

    if (!(Test-Path $Ps1FullPath))
    {
        throw "Could not find $Ps1FullPath"
    }

    Copy-Item -Path $Ps1FullPath -Destination $ExeFullPath -Force
}

function Lock-File
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [String] $FullPath
    )
    return [System.IO.File]::Open($FullPath, 'Open', 'Read', 'Read')
}

function Ensure-MaximumOneMatchingProcessRunning
{
    Param (
		[Parameter(Mandatory = $true)]
		[string] $ExeFullPath,

		[Parameter(Mandatory = $true)]
		[scriptblock] $ProcessPredicate,

		[Parameter(Mandatory = $true)]
        [Object] $EtwProvider,

		[Parameter(Mandatory = $true)]
        [String] $RuleName
    )

    $ExeDirPath = Split-Path -Path $ExeFullPath -Parent
    $DdcPath = Split-Path -Path $ExeDirPath -Parent
	$ExeName = Split-Path -Path $ExeFullPath -Leaf
    $MatchingProcesses = @(Get-CimInstance Win32_Process -Filter "name = '$ExeName'" | Where-Object { $_.Path -ilike "$DdcPath*$ExeName" })
    if ($MatchingProcesses.length -eq 0)
    {
        return $false;
    }

    if ($MatchingProcesses.length -gt 1)
    {

        Write-GenericEventData -RuleName $RuleName -EventName "ProcessResult" -EventInformation "There were $($MatchingProcesses.length) matching processes" -EtwProvider $EtwProvider

        foreach ($ProcessObj in $MatchingProcesses)
        {
            Stop-Process -id $ProcessObj.ProcessId -Force
        }
        return $false;
    }

    $MatchingProcess = $MatchingProcesses | Select-Object -First 1

    $ShouldStopProcess = !(Invoke-Command -ScriptBlock $ProcessPredicate -ArgumentList $MatchingProcess)
    if ($ShouldStopProcess)
    {
        Stop-Process -id $MatchingProcess.ProcessId -Force
        return $false
    }

    return $true
}




function Test-ExeSigned
{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[String] $ExeFullPath,

		[Parameter(Mandatory = $true)]
		[string[]] $Thumbprints,

		[Parameter(Mandatory = $true)]
		[string] $ExpectedHash,

        [parameter(Mandatory = $false)]
        [switch] $DevMode
	)

    if (!$DevMode)
    {
        Test-VerifiedFile $ExeFullPath $Thumbprints $ExpectedHash
    }
}

function Start-GuardedProcess
{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[String] $ExePath,

		[Parameter(Mandatory = $true)]
		[string[]] $Thumbprints,

		[Parameter(Mandatory = $true)]
		[string] $ExpectedHash,

		[Parameter(Mandatory = $true)]
		[scriptblock] $ProcessPredicate,

		[Parameter(Mandatory = $true)]
		[scriptblock] $InvokeProcess,

		[Parameter(Mandatory = $true)]
		[Object] $EtwProvider,

		[Parameter(Mandatory = $true)]
		[string] $RuleName,

        [parameter(Mandatory = $false)]
        [switch] $DevMode
	)

    $ExeLock = $null
    try
    {
        $ExeLock = Lock-File -FullPath $ExePath

        Test-ExeSigned -ExeFullPath $ExePath -Thumbprints $Thumbprints -ExpectedHash $ExpectedHash -DevMode:$DevMode

        if (Ensure-MaximumOneMatchingProcessRunning -ExeFullPath $ExePath -ProcessPredicate $ProcessPredicate -EtwProvider $EtwProvider -RuleName $RuleName)
        {
            return 'Process already running'
        }

		$Proc = Invoke-Command $InvokeProcess
        $Handle = $Proc.Handle # cache proc.Handle

        # give the tool time to start before querying it
        Wait-Process -Timeout 10 -Id $Proc.Id -ErrorAction SilentlyContinue

        if ($Proc.hasExited)
        {
            return "Process failed to start with error code $($Proc.ExitCode)"
        }

        if (!(Ensure-MaximumOneMatchingProcessRunning -ExeFullPath $ExePath -ProcessPredicate $ProcessPredicate -EtwProvider $EtwProvider -RuleName $RuleName))
        {
            return 'Process found after starting'
        }
    }
    finally
    {
        if ($null -ne $ExeLock)
        {
            [void]$ExeLock.Dispose()
        }
    }
    return 'Finished successfully'
}

$SAFEPROCESS_CS_263334240 = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ComponentModel;

public static class SafeProcess
{
    #region Consts
    public const int TOKEN_QUERY = 0x00000008;
    public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
    private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const int CREATE_NO_WINDOW = 0x08000000;
    public const UInt32 DISABLE_MAX_PRIVILEGE = 0x1;
    public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
    public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const UInt32 TOKEN_DUPLICATE = 0x0002;
    public const UInt32 TOKEN_IMPERSONATE = 0x0004;
    public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
    public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
    public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
    public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
    public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
    public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
        TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
        TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
        TOKEN_ADJUST_SESSIONID);

    private const string c_LocalServiceSid = "S-1-5-19";
    #endregion

    #region P/Invoke
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateRestrictedToken(
        IntPtr ExistingTokenHandle,
        UInt32 Flags,
        UInt32 DisableSidCount,
        IntPtr SidsToDisable,
        UInt32 DeletePrivilegeCount,
        IntPtr PrivilegesToDelete,
        UInt32 RestrictedSidCount,
        IntPtr SidsToRestrict,
        out IntPtr NewTokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(
    IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(
    IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
    IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("advapi32.dll", SetLastError = true, BestFitMapping = false, ThrowOnUnmappableChar = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LogonUser(
        [MarshalAs(UnmanagedType.LPStr)] string pszUserName,
        [MarshalAs(UnmanagedType.LPStr)] string pszDomain,
        [MarshalAs(UnmanagedType.LPStr)] string pszPassword,
        int dwLogonType,
        int dwLogonProvider,
        ref IntPtr phToken);

    [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        Int32 ImpersonationLevel,
        Int32 dwTokenType,
        ref IntPtr phNewToken);

	[DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandle,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessAsUser(
        IntPtr hToken,
        String lpApplicationName,
        String lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandle,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        String lpCurrentDirectory,
        ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateEnvironmentBlock(
        ref IntPtr lpEnvironment,
        IntPtr hToken,
        bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DestroyEnvironmentBlock(
        IntPtr lpEnvironment);

    [DllImport("user32.dll")]
    static extern uint WaitForInputIdle(
        IntPtr hProcess,
        uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern int GetLastError();

    #endregion

    #region StaticMethods
    public static bool LogonAsLocalService(out IntPtr token)
    {
        token = IntPtr.Zero;
        SecurityIdentifier securityIdentifier = new SecurityIdentifier(c_LocalServiceSid);
        IdentityReference user = securityIdentifier.Translate(typeof(NTAccount));
        string[] splitted = user.Value.Split('\\');
        if (splitted.Length != 2)
        {
            return false;
        }

        string domainName = splitted[0];
        string userName = splitted[1];
        const int LOGON32_PROVIDER_DEFAULT = 0;
        const int LOGON32_LOGON_SERVICE = 5;
        if (!LogonUser(
            userName,
            domainName,
            null,
            LOGON32_LOGON_SERVICE,
            LOGON32_PROVIDER_DEFAULT,
            ref token))
        {
            return false;
        }
        return true;
    }

    public static bool CreatePrimaryToken(IntPtr hToken, ref IntPtr newToken)
    {
        newToken = IntPtr.Zero;
        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.nLength = (uint)Marshal.SizeOf(sa);
        if (!DuplicateTokenEx(
        hToken,
        TOKEN_ALL_ACCESS,
        ref sa,
        (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
        (int)TOKEN_TYPE.TokenPrimary,
        ref newToken))
        {
            return false;
        }
        return true;
    }

    public static bool CreateEnv(IntPtr token, out IntPtr envBlock)
    {
        envBlock = IntPtr.Zero;
        if (!CreateEnvironmentBlock(ref envBlock, token, false))
        {
            return false;
        }
        return true;
    }

    public static bool RemovePrivilegesFromToken(IntPtr token, out IntPtr newToken)
    {
        newToken = IntPtr.Zero;
        if (!CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 0, IntPtr.Zero, 0, IntPtr.Zero, 0, IntPtr.Zero, out newToken))
        {
            return false;
        }
        return true;
    }

    public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    public const int PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
    public const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;
    public const UInt32 FLAGS = (CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT);

    public static STARTUPINFOEX GetSafeStartupInfo()
    {
        STARTUPINFOEX st = new STARTUPINFOEX { };

        const long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = (((long)1) << 44);
        const long PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON = (((long)1) << 32);
        const long PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON = (((long)1) << 60);

        var lpSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize); // Ignoring the return value because it will fail by design
        if (lpSize == IntPtr.Zero)
        {
            throw new Win32Exception(GetLastError(), "Failed to allocate ProcThreadAttributeList");
        }

        st.lpAttributeList = Marshal.AllocHGlobal(lpSize);
        var success = InitializeProcThreadAttributeList(st.lpAttributeList, 2, 0, ref lpSize);
        if (!success)
        {
            throw new Win32Exception(GetLastError(), "Failed to initialize ProcThreadAttributeList");
        }

        IntPtr lpMitigationPolicy = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteInt64(lpMitigationPolicy, PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
            | PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
            | PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON);

        success = UpdateProcThreadAttribute(
            st.lpAttributeList,
            0,
            (IntPtr)PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            lpMitigationPolicy,
            (IntPtr)IntPtr.Size,
            IntPtr.Zero,
            IntPtr.Zero);
        if (!success)
        {
            throw new Win32Exception(GetLastError(), "Failed to update mitigation policy");
        }

        st.StartupInfo.cb = (uint)Marshal.SizeOf(st);
        st.StartupInfo.wShowWindow = 0;
        st.StartupInfo.lpDesktop = null; // inheritats the parent process desktop - sessionId 0
        st.StartupInfo.dwFlags = 0x0;
        return st;
    }

    public static int CreateSafeProcessAsUser(IntPtr token, string path, IntPtr envBlock, string profilePath = null, string args = null)
    {
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION { };
        STARTUPINFOEX st = GetSafeStartupInfo();
        if (!CreateProcessAsUser(token, path, args, IntPtr.Zero, IntPtr.Zero, false, FLAGS, envBlock, profilePath, ref st, out pi))
        {
            throw new Win32Exception(GetLastError(), "Failed to start process as user");
        }
        if (pi.hProcess != IntPtr.Zero)
        {
            WaitForInputIdle(pi.hProcess, 3000);
            CloseHandle(pi.hProcess);
        }
        return (int)pi.dwProcessId;
    }

	public static int CreateSafeProcess(string path, string args)
    {
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION { };
        STARTUPINFOEX st = GetSafeStartupInfo();
        if (!CreateProcess(path, args, IntPtr.Zero, IntPtr.Zero, false, FLAGS, IntPtr.Zero, null, ref st, out pi))
        {
            throw new Win32Exception(GetLastError(), "Failed to start process");
        }

        if (pi.hProcess != IntPtr.Zero)
        {
            WaitForInputIdle(pi.hProcess, 3000);
            CloseHandle(pi.hProcess);
        }
        return (int)pi.dwProcessId;
    }

    public static int CreateSafeProcessAsLocalService(string path, string args)
    {
        IntPtr token;
        bool success = false;
        success = LogonAsLocalService(out token);
        if (!success)
        {
            throw new Win32Exception(GetLastError(), "Failed to logon as local service");
        }

        IntPtr env;
        success = CreateEnv(token, out env);
        if (!success)
        {
            throw new Win32Exception(GetLastError(), "Failed to create environment block for local service");
        }
        return CreateSafeProcessAsUser(token, path, env, null, args);
    }

    public static void CloseHandles(IntPtr[] handles)
    {
        foreach (var handle in handles)
        {
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
            }
        }
    }
    #endregion

    #region Structs
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public uint nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROC_THREAD_ATTRIBUTE
    {
        IntPtr Attribute;
        IntPtr lpValue;
        uint cbSize;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    #endregion

    #region Enums
    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    internal enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }
    #endregion
}
"@
Add-Type -TypeDefinition $SAFEPROCESS_CS_263334240 -Language CSharp -IgnoreWarnings

# Creates a process that has security mitigations applied to it.
function Start-SafeProcess
{
    [CmdletBinding()]
    param (
        # A path to an exectuable.
        [Parameter(Mandatory=$true)]
        [string] $FilePath,

        # A list of arguments to pass to the exectuable.
        [Parameter()]
        [string[]] $ArgumentList,

        # Run process as local service
        [Parameter()]
        [switch] $AsLocalService
    )
    $commandline = "`"$FilePath`" $($ArgumentList -join " ")"

    if ($AsLocalService)
    {
        $processId = [SafeProcess]::CreateSafeProcessAsLocalService($FilePath, $commandline)
    }
    else
    {
        $processId = [SafeProcess]::CreateSafeProcess($FilePath, $commandline)
    }
    return Get-Process -Id $processId
}

#------------------------------------------------------------ Common Modules  -------------------------------------------

#------------------------------------------------------------ CloudConfiguration  ---------------------------------------
if ($PSVersionTable.PSVersion.Major -gt 5)
{
    
    $HTTP_CS_2596268328 = @"
using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace Http
{
    public class CloudConfigurationRootCertificateException : Exception
    {
        public CloudConfigurationRootCertificateException(string rootCert)
        {
            this.m_rootCert = rootCert;
        }

        public override string ToString()
        {
            return "Failed verification of root certificate. Root element: " + m_rootCert;
        }

        private string m_rootCert;
    };

    public class CloudConfigurationCertificateChainException : Exception
    {
        public CloudConfigurationCertificateChainException(string failureStatus)
        {
            this.m_failureStatus = failureStatus;
        }

        public override string ToString()
        {
            return "Failed signature verification: certificate chain validation failed with " +m_failureStatus;
        }

        private string m_failureStatus;
    }

    public class Certificates
    {
        private static bool ValidateChain(X509Chain chain)
        {
            if (chain.ChainStatus.Length == 0)
            {
                return true;
            }
            var status = chain.ChainStatus[0].Status;
            return status != X509ChainStatusFlags.NoError;
        }

        public static string SendHttpWithRootCaVerification(string uri, string caThumbprint, int index = 1)
        {
            X509Certificate2 certificate = null;
            HttpClientHandler httpClientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, cert, __, ___) =>
                {
                    certificate = new X509Certificate2(cert.GetRawCertData());
                    return true;
                }
            };

            HttpClient httpClient = new HttpClient(httpClientHandler);
            using (HttpResponseMessage response = httpClient.Send(new HttpRequestMessage(HttpMethod.Get, uri)))
            {
                if (certificate == null)
                {
                    throw new CloudConfigurationRootCertificateException("No Certificate");
                }
                var chain = new X509Chain();
                if (!chain.Build(certificate) || !ValidateChain(chain))
                {
                    throw new CloudConfigurationCertificateChainException(String.Join(",", chain.ChainStatus.Select(s => s.Status.ToString())));
                }
                var rootCert = chain.ChainElements[chain.ChainElements.Count - index].Certificate;
                if (rootCert.Thumbprint.ToUpper() != caThumbprint)
                {
                    throw new CloudConfigurationRootCertificateException(rootCert.Thumbprint);
                }
                var outputStream = new StreamReader(response.Content.ReadAsStream());
                return outputStream.ReadToEnd();
            }
        }
    }
}
"@
Add-Type -TypeDefinition $HTTP_CS_2596268328 -Language CSharp -IgnoreWarnings
}
else
{
    Add-Type -AssemblyName System.Web
}

class CloudConfigurationException : Exception
{}

class CloudConfigurationSha1SignatureValidationException : CloudConfigurationException
{
    [String] ToString()
    {
        return 'Failed signature verification: mismatching SHA1'
    }
}

class CloudConfigurationSha256SignatureValidationException : CloudConfigurationException
{
    [String] ToString()
    {
        return 'Failed signature verification: mismatching SHA256'
    }
}

class CloudConfigurationCertificateChainException : CloudConfigurationException
{
    [String] $FailureStatus

    [String] ToString()
    {
        return "Failed signature verification: certificate chain validation failed with $($this.FailureStatus)"
    }
}

class CloudConfigurationWebException : CloudConfigurationException
{
    [System.Net.WebException] $WebException

    [String] ToString()
    {
        return "Failed with WebException: $($this.WebException.ToString())"
    }
}

class CloudConfigurationRootCertificateException : CloudConfigurationException
{
    [String] $RootCert

    [String] ToString()
    {
        return "Failed verification of root certificate. Root element: $($this.RootCert)"
    }
}

class CloudConfigurationParseResponseException : CloudConfigurationException
{
    [String] $ConfigNameRegex
    [Exception] $Exception

    [String] ToString()
    {
        return "Failed finding configuration named '$($this.ConfigNameRegex)' with exception: $($this.Exception.ToString())"
    }
}

class CloudConfigurationParseConfigBodyException : CloudConfigurationException
{
    [Exception] $Exception

    [String] ToString()
    {
        return "Failed with WebException: $($this.WebException.ToString())"
    }
}

class CloudConfigurationMissingConfigNameException : CloudConfigurationException
{
    [String] ToString()
    {
        return 'Failed converting config body to json'
    }
}

class CloudConfigParameters
{
    [String] $MachineId
    [String] $ComputerDnsName
    [String] $TenantId
    [String] $ClientVersion
    [String] $GroupIds
    [String] $ProductType
    [String] $OsType
    [String] $ShieldsUpConfigVer
    [String] $ShieldsUpConfigHash
    [String] $ScriptVer
}

function Convert-Base64StringToCert
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $CertStr
    )

    return [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($CertStr))
}

function Test-ChainStatusValid
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Chain] $Chain,

        [Switch] $IgnoreCertTime
    )

    if ($Chain.ChainStatus.Length -eq 0)
    {
        return $true
    }

    $CheckStatus = $Chain.ChainStatus[0].Status
    $IsError = $CheckStatus -ne [Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError
    $IsErrorInvalidTime = $Chain.ChainStatus.Length -eq 1 -And $CheckStatus -eq [Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotTimeValid
    return !$IsError -Or $IgnoreCertTime -And $IsErrorInvalidTime
}

function Test-CertificateSignature
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $CertObj,

        [Parameter(Mandatory = $true)]
        [Byte[]] $BodyBytes,

        [Parameter(Mandatory = $true)]
        [Byte[]] $SignatureBytes,

        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.HashAlgorithmName] $Algorithm,

        [Parameter()]
        [System.Security.Cryptography.RSASignaturePadding] $Padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )

    if ($PSVersionTable.PSVersion.Major -gt 5)
    {
        $VerifyData = {
            param(
                [Byte[]] $Signature
            )
            return $CertObj.PublicKey.GetRSAPublicKey().VerifyData($BodyBytes, $Signature, $Algorithm, $Padding)
        }
    }
    else
    {
        $VerifyData = {
            param(
                [Byte[]] $Signature
            )
            $OID = [System.Security.Cryptography.CryptoConfig]::MapNameToOID($Algorithm.Name)
            return $CertObj.PublicKey.Key.VerifyData($BodyBytes, $OID, $Signature)
        }
    }

    # Reverse first as it is more likely to succeed
    [array]::Reverse($SignatureBytes)
    $Res = $VerifyData.Invoke($SignatureBytes)
    if (!$Res)
    {
        [array]::Reverse($SignatureBytes)
        $Res = $VerifyData.Invoke($SignatureBytes)
    }
    return $Res
}

function Validate-ConfigSignatures
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $Body,

        [Parameter(Mandatory = $true)]
        [String] $Signature,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String] $Signature256,

        [Parameter(Mandatory = $true)]
        [String] $Cert,

        [Parameter(Mandatory = $true)]
        [String[]] $CertChain,

        [Switch] $IgnoreCertTime
    )

    $CertObj = Convert-Base64StringToCert($Cert)
    $BodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)

    $SignatureBytes = [System.Convert]::FromBase64String($Signature)
    if (!(Test-CertificateSignature $CertObj $BodyBytes $SignatureBytes SHA1))
    {
        throw New-Object CloudConfigurationSha1SignatureValidationException
    }

    if ($Signature256 -ne '')
    {
        $SignatureBytes = [System.Convert]::FromBase64String($Signature256)
        if (!(Test-CertificateSignature $CertObj $BodyBytes $SignatureBytes SHA256))
        {
            throw New-Object CloudConfigurationSha256SignatureValidationException
        }
    }

    $Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $CertChain | ForEach-Object { Convert-Base64StringToCert($_) } | ForEach-Object { [void]$Chain.ChainPolicy.ExtraStore.Add($_) }
    $Chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
    $Chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck

    [void]$Chain.Build($CertObj)
    if (!(Test-ChainStatusValid $Chain -IgnoreCertTime:$IgnoreCertTime))
    {
        throw New-Object CloudConfigurationCertificateChainException -Property @{
            FailureStatus = $CheckStatus
        }
    }
}

function Invoke-WebRequestWithRootCaVerification
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri] $Uri,

        [Parameter()]
        [switch] $IsStgEnv
    )

    $MsRootThumbprint = '8F43288AD272F3103B6FB1428485EA3014C0BCFE'
    $MsAzureThumbprint = '2F2877C5D778C31E0F29C7E371DF5471BD673173'
    
    if ($PSVersionTable.PSVersion.Major -gt 5)
    {
        $RootCAThumbprint = if ($IsStgEnv) { $MsAzureThumbprint } else { $MsRootThumbprint }
        $Index = if ($IsStgEnv) { 2 } else { 1 }
        return [Http.Certificates]::SendHttpWithRootCaVerification($Uri, $RootCAThumbprint, $Index);
    }

    $Request = [System.Net.HttpWebRequest]::Create($Uri)

    try
    {
        $Resp = $Request.GetResponse()
        $BodyStreamReader = New-Object System.IO.StreamReader($Resp.GetResponseStream())
        $BodyRes = $BodyStreamReader.ReadToEnd()
    }
    catch [System.Net.WebException]
    {
        throw New-Object CloudConfigurationWebException -Property @{
            WebException = $_.Exception
        }
    }
    finally
    {
        if ($Resp)
        {
            $Resp.Dispose()
        }
    }

    $Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    if (!$Chain.Build($Request.ServicePoint.Certificate) -Or !(Test-ChainStatusValid $Chain))
    {
        throw New-Object CloudConfigurationCertificateChainException -Property @{
            FailureStatus = $Chain.ChainStatus[0].Status
        }
    }

    $RootValidated = $false
    if ($IsStgEnv)
    {
        $RootCert = $Chain.ChainElements[$Chain.ChainElements.Count - 2].Certificate
        $RootValidated = $RootCert.Thumbprint.ToUpperInvariant() -eq $MsAzureThumbprint
    }
    else
    {
        $RootCert = $Chain.ChainElements[$Chain.ChainElements.Count - 1].Certificate
        $RootValidated = $RootCert.Thumbprint.ToUpperInvariant() -eq $MsRootThumbprint
    }

    if (!$RootValidated)
    {
        throw New-Object CloudConfigurationRootCertificateException -Property @{
            RootCert = $RootCert
        }
    }

    return $BodyRes
}

function Parse-CloudConfigResponse
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $ConfigJson,

        [Parameter(Mandatory = $true)]
        [String] $ConfigNameRegex
    )

    try
    {
        $FullConfig = ConvertFrom-Json -InputObject $ConfigJson
        foreach ($Config in $FullConfig)
        {
            $Body = $Config.Body
            $cmdJson = $Body | ConvertFrom-Json
            if ($cmdJson.cmd.type -match $ConfigNameRegex)
            {
                return @{
                    Signature        = $Config.sig
                    Signature256     = $Config.sha256sig
                    Certificate      = $Config.Cert
                    CertificateChain = $Config.Chain
                    Body             = $Body
                }
            }
        }
    }
    catch
    {
        throw New-Object CloudConfigurationParseResponseException -Property @{
            Exception = $_.Exception
        }
    }

    return $null
}

function Get-ConfigFromCloud
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $CloudGateway,

        [Parameter(Mandatory = $true)]
        [CloudConfigParameters] $ConfigParameters
    )

    $Request = [System.UriBuilder]"$CloudGateway/commands"

    $Parameters = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
	$Parameters['productType'] = $ConfigParameters.ProductType
	$Parameters['clientver'] = $ConfigParameters.ClientVersion
	$Parameters['configVer'] = '0.0.0.0.'
	$Parameters['tenantid'] = $ConfigParameters.TenantId
	$Parameters['machineid'] = $ConfigParameters.MachineId
	$Parameters['computerDnsName'] = $ConfigParameters.ComputerDnsName
	$Parameters['groupIds'] = $ConfigParameters.GroupIds
	$Parameters['osType'] = $ConfigParameters.OsType
	$Parameters['shieldsUpConfigurationVersion'] = $ConfigParameters.ShieldsUpConfigVer
	$Parameters['shieldsUpConfigurationHash'] = $ConfigParameters.ShieldsUpConfigHash
	$Parameters['scriptVer'] = $ConfigParameters.ScriptVer

    $Request.Query = $Parameters.ToString()

    $IsStgEnv = $CloudGateway -ilike '*wdatpstg-eus2*'

    # TODO - change endpoint once Cloud is ready with new config
    return Invoke-WebRequestWithRootCaVerification $Request.Uri.TosTring() -IsStgEnv:$IsStgEnv
}

function Parse-CloudConfig
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $ConfigJson,

        [Parameter(Mandatory = $true)]
        [String] $ConfigNameRegex
    )

    $Resp = Parse-CloudConfigResponse $ConfigJson $ConfigNameRegex
    if ($null -eq $Resp)
    {
        throw New-Object CloudConfigurationMissingConfigNameException
    }

    Validate-ConfigSignatures $Resp.$Body $Resp.$Signature $Resp.$Signature256 $Resp.$Certificate $Resp.$CertificateChain

    try
    {
        return $Resp.$Body | ConvertFrom-Json
    }
    catch
    {
        throw New-Object CloudConfigurationParseConfigBodyException -Property @{
            Exception = $_.Exception
        }
    }
}



#-------------------------------------------------------- CloudConfiguration End  ---------------------------------------

#-------------------------------------------------------------- Registry  -----------------------------------------------
function Get-RegistryKey
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $KeyPath
    )

    return Get-Item -Path $KeyPath
}

function Get-RegistryKeyValue
{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [Microsoft.Win32.RegistryKey] $RegObject,

        [Parameter(ValueFromPipeline = $false, Mandatory = $true)]
        [String] $KeyName
    )

    return $RegObject | Get-ItemProperty -Name $KeyName | Select-Object -ExpandProperty $KeyName
}

function Get-RegistrySubkeys
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $KeyPath
    )

    try
    {
        [Array] $Subkeys = Get-ChildItem -Path $KeyPath
        return Write-Output -NoEnumerate $Subkeys
    }
    catch
    {
        return Write-Output -NoEnumerate @()
    }
}

function Read-RegistryKey
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $KeyName,

        [Parameter(Mandatory = $true)]
        [String] $KeyPath
    )

    try
    {
        return Get-ItemProperty -Path $KeyPath -Name $KeyName | Select-Object -ExpandProperty $KeyName
    }
    catch
    {
        return $null
    }
}



#------------------------------------------------------------ Registry End  ---------------------------------------------
#------------------------------------------------------------------------------------------------------------------------

#------------------------------------------------------------- SenseConfig  ---------------------------------------------
class SenseConfigException : Exception
{}

class SenseConfigOnboardedDataException : SenseConfigException
{
    [Exception] $Exception

    [String] ToString()
    {
        return "Failed to get onboarded data from registry: $($this.Exception.ToString())"
    }
}

class SenseConfigOnboardedDataParsingException : SenseConfigException
{
    [Exception] $Exception

    [String] ToString()
    {
        return "Failed parsing onboarded data json: $($this.Exception.ToString())"
    }
}

$SENSE_REGISTRY_ROOT = "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection"

function Get-SenseMachineId {
    [CmdletBinding()]
    param ()
    return Get-ItemPropertyValue -Path $SENSE_REGISTRY_ROOT -Name "senseId"
}

function Get-SenseOrgId {
    [CmdletBinding()]
    param ()
    return Get-ItemPropertyValue -Path "$SENSE_REGISTRY_ROOT\Status" -Name "OrgId"
}

function Get-OnboardedData
{
    $OnboardedDataJson = Read-RegistryKey 'OnboardedInfo' $SENSE_REGISTRY_ROOT

    try
    {
        $OnboardedData = ConvertFrom-Json -InputObject $OnboardedDataJson
    }
    catch
    {
        throw New-Object SenseConfigOnboardedDataException -Property @{
            Exception = $_.Exception
        }
    }

    $Body = $OnboardedData.Body
    $Signature = $OnboardedData.sig
    $Signature256 = $OnboardedData.sha256sig
    $Cert = $OnboardedData.Cert
    $CertChain = $OnboardedData.Chain

    Validate-ConfigSignatures $Body $Signature $Signature256 $Cert $CertChain -IgnoreCertTime

    return $Body
}

function Get-CloudGateway
{
    $OnboardingDataBodyJson = Get-OnboardedData
    try
    {
        $OnboardingDataBody = ConvertFrom-Json -InputObject $OnboardingDataBodyJson
    }
    catch
    {
        throw New-Object SenseConfigOnboardedDataParsingException -Property @{
            Exception = $_.Exception
        }
    }

    $CloudGateway = $OnboardingDataBody.geoLocationUrl
    if ($CloudGateway[$CloudGateway.Length - 1] -eq "/")
    {
        $CloudGateway = $CloudGateway.Substring(0, $CloudGateway.Length - 1)
    }

    return $CloudGateway
}



#------------------------------------------------------------ SenseConfig End  ------------------------------------------


class UndefinedFeatureFlagResultException : Exception
{
    [string] $FeatureFlag
    [string] $Result

    [String] ToString()
    {
        return "Undefined feature flag result: $($this.Result.ToString()). FeatureFlag: $($this.FeatureFlag.ToString())"
    }
}

function Test-FeatureFlagIsOn
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $FeatureEndpoint
    )
    $CloudGateway = Get-CloudGateway
    $MachineId = Get-SenseMachineId
    $OrgId = Get-SenseOrgId
    
    $featureFlagResult = Invoke-WebRequestWithRootCaVerification "$CloudGateway/commands/$FeatureEndpoint`?machineId=$MachineId&orgId=$OrgId"
    if ($featureFlagResult -eq "false")
    {
        return $false
    }
    if ($featureFlagResult -ne "true")
    {
        throw New-Object UndefinedFeatureFlagResultException -Property @{
            FeatureFlag = $FeatureEndpoint
            Result = $featureFlagResult
        }
    }
    return $true
}
$SHIELDSUPSETUPETW_CS_105563744 = @"
using System;
using System.Text;
using System.Diagnostics.Tracing;
using Microsoft.PowerShell.Commands;

[EventSource(Name = "Microsoft.Windows.NdrScanner", Guid = "a4bfed93-f051-4c33-a524-8ccc50d0dd2b")]
public sealed class ShieldsUpSetupEventSource : EventSource
{
    public ShieldsUpSetupEventSource() : base(EventSourceSettings.EtwSelfDescribingEventFormat) { }
}

[EventData] // [EventData] makes it possible to pass an instance of the class as an argument to EventSource.Write().
public class ShieldsUpSetupResultsEvent
{
    public String ScriptVersion { get; set; }
	public String ErrorString { get; set; }
    public bool OperationalMode { get; set; }
}
"@
Add-Type -TypeDefinition $SHIELDSUPSETUPETW_CS_105563744 -Language CSharp -IgnoreWarnings

Set-Variable SCRIPT_VERSION -Option Constant -Value '3.8.0'
Set-Variable MDE_CONTAIN_GUID_NAME -Option Constant -Value '213c521e-6a42-4076-a902-e088e1f1d3e9'
Set-Variable MDE_CONTAIN_NAME -Option Constant -Value 'MDEContainToolV2'
Set-Variable MDE_CONTAIN_EXE_NAME -Option Constant -Value ($MDE_CONTAIN_NAME + '.exe')
Set-Variable MDE_CONTAIN_PS1_NAME -Option Constant -Value ($MDE_CONTAIN_GUID_NAME + '.ps1')
Set-Variable MDE_CONTAIN_EXPECTED_HASH -Option Constant -Value 'FDC0624F6B286EC5887F625D76A2535D3C088991FDBE1288B04AB0424429142B'
Set-Variable MDE_CONTAIN_COMPRESSED_EXPECTED_HASH -Option Constant -Value 'CFC614F13305E074BA16EF860898C6F459B18980D9A04ABBE455C50355A38D01'
Set-Variable MDE_CONTAIN_THUMBPRINTS -Option Constant -Value @(
    '8740DF4ACB749640AD318E4BE842F72EC651AD80',
	'BB983EC3E1F76DE6C1E8446C9976A82BD1798BB7',
	'AFBF0B8B6A18F7E23CCA1DDCD0AC1A55B4035173'
)
Set-Variable MDE_CONTAIN_FEATURE_FLAG_NAME -Option Constant -Value 'isenabled2'

Class AggregatedEtwProvider
{
    [String]$ScriptVersion
    [Collections.Generic.List[String]] $Messages
    [Object]$Provider

    AggregatedEtwProvider($Provider, $ScriptVersion)
    {
        $this.ScriptVersion = $ScriptVersion
        $this.Messages = New-Object Collections.Generic.List[String]
        $this.Provider = $Provider
    }

    Write($Message)
    {
        [void]$this.Messages.add($Message)
    }

    Write($RuleName, $EventData)
    {
        [void]$this.Messages.add($EventData.Information)
    }

    Flush()
    {
        $AggregatedMsg = ConvertTo-Json -Compress -InputObject $this.Messages
        $EtwEvent = New-Object ShieldsUpSetupResultsEvent -Property @{
            ScriptVersion   = $this.ScriptVersion
            ErrorString     = $AggregatedMsg
            OperationalMode = $true
        }

        $this.Provider.Write("ShieldsUpSetupResultsEvent", $EtwEvent)
    }
}

function Using-Object
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object] $Object,
        [Parameter(Mandatory = $true)]
        [scriptblock] $Block
    )

    try
    {
        Invoke-Command -ScriptBlock $Block
    }
    finally
    {
        if($null -ne $Object)
        {
            $Object.Dispose()
        }
    }
}

function Deploy-BinaryLZMA
{
	param(
		[Parameter(Mandatory=$true)]
		[string] $SourceDirectory,
		[Parameter(Mandatory=$true)]
		[string] $TargetDirectory
	)

    if ( Test-Path $ExeFullPath -PathType Leaf )
    {
        return
    }

    Using-Object (Lock-File -FullPath $Ps1FullPath) {
		Test-FileHash -FilePath $Ps1FullPath -ExpectedFileHash $MDE_CONTAIN_COMPRESSED_EXPECTED_HASH
		Decompress-LZMA $Ps1FullPath $ExeFullPath
	}
}

Write-Host "Setup version $SCRIPT_VERSION"

$EtwProvider = [AggregatedEtwProvider]::new([ShieldsUpSetupEventSource]::new(), $SCRIPT_VERSION)

try
{
    Write-Host "Testing FeatureFlag for MdeContain"

    if (!(Test-FeatureFlagIsOn $MDE_CONTAIN_FEATURE_FLAG_NAME))
    {
        Write-Host "FeatureFlag for MdeContain is off"
        return
    }
    
    Write-Host "FeatureFlag for MdeContain is on"

    $Ps1FullPath = Join-Path $PSScriptRoot $MDE_CONTAIN_PS1_NAME
	$ExeFullPath = Join-Path $PSScriptRoot $MDE_CONTAIN_EXE_NAME

	Write-Host "Extracting tool"
	Deploy-BinaryLZMA -SourceDirectory $Ps1FullPath -TargetDirectory $ExeFullPath

	$ProcessPredicate =
	{
		param(
			[Parameter(Mandatory=$true)]
			[object] $Process
		)

        return $Process.ExecutablePath -eq $ExeFullPath
	}

	$InvokeProcess =
	{
		return Start-SafeProcess -FilePath $ExeFullPath
	}

	Write-Host "Starting tool"
    $result = Start-GuardedProcess `
		-ExePath $ExeFullPath `
		-Thumbprints ([array]$MDE_CONTAIN_THUMBPRINTS) `
		-ExpectedHash $MDE_CONTAIN_EXPECTED_HASH `
		-ProcessPredicate $ProcessPredicate `
		-InvokeProcess $InvokeProcess `
		-EtwProvider $EtwProvider `
		-RuleName 'UnusedRuleName'

    $Message = "Finished with result: $result"
    Write-Host $Message
    $EtwProvider.Write($Message)
}
catch
{
	$ErrorString = Get-SlimException $_ | ConvertTo-Json -Compress
    $EtwProvider.Write($ErrorString)
}

$EtwProvider.Flush()
# SIG # Begin signature block
# MIInzAYJKoZIhvcNAQcCoIInvTCCJ7kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA3f5GtFuVZweFr
# rrzLw687qtrR0GXj0gNjAk4XNqUhDKCCDZcwggYVMIID/aADAgECAhMzAAADEBr/
# fXDbjW9DAAAAAAMQMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwODA0MjAyNjM5WhcNMjMwODAzMjAyNjM5WjCBlDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE+MDwGA1UEAxM1TWlj
# cm9zb2Z0IFdpbmRvd3MgRGVmZW5kZXIgQWR2YW5jZWQgVGhyZWF0IFByb3RlY3Rp
# b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0y67idUrLERDl3ls1
# 1XkmCQNGqDqXUbrM7xeQ3MDX2TI2X7/wxqqVBo5wjSGMUEUxZpgrQRj7fyyeQWvy
# OKx7cxcBYXxRWjOQRSYWqk+hcaLj7E9CkuYyM1tuVxuAehDD1jqwLGS5LfFG9iE9
# tXCQHI59kCLocKMNm2C8RWNNKlPYN0dkN/pcEIpf6L+P+GXYN76jL+k7uXY0Vgpu
# uKvUZdxukyqhYbWy8aNr8BasPSOudq2+1VzK52kbUq79M7F3lN+JfDdyiG5YoSdc
# XDrvOU1fnP1Kc4PtUJL7tSHFuBylTiNyDnHfSORQeZPFg971CeZS7I8ZFojDLgTY
# kDQDAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBggrBgEFBQcDAwYKKwYBBAGCN0wv
# ATAdBgNVHQ4EFgQU0X7BWbJmeu82AxuDs7MBJC8zJ8swRQYDVR0RBD4wPKQ6MDgx
# HjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEWMBQGA1UEBRMNNDUxODk0
# KzQ3MjIyMDAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8E
# TTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9N
# aWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBR
# BggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAw
# DQYJKoZIhvcNAQELBQADggIBAIXZp9/puv2exE6jflkfuJ3E8xrXA1ch9bnCloXS
# 01xOXTauGU/+1peumenJbgwCzn/iwGIJkuoHSx5F85n7OG9InPRApTNcYmAkGPIk
# /x5SNl67Su8eHlLGd8erjoEcseZBckRENr5mBHtELtOWR80cAH9dbALlY/gJ5FDq
# jOxA9Q6UDeaT9oeIJwSy/LD9sUKrUZ4zSvqFBjjEBx3g2TfmRe3qLfKJEOL1mzCk
# 06RHYwcU2uU1s5USCeePuafeQ159io+FVdW5f7703UeD4pzXOp4eZTtWl0875By+
# bWxAR8/dc41v2MEQoy0WplbGfkBm9BWT0w0pL3itBYcXRlzIfPForBPK2aIQOMPL
# CH8JR3uJXvbTJ5apXBAFOWl6dU1JqGTT/iuWsVznHBqDmq6zKf38QYocac0o7qL3
# RG1/eiQdbPQisNpFiqTzTd6lyUaXrPtk+BniKT4bVXJ2FrfsmLiXIcFhC6FAidok
# spWZVHS8T4WwSPVpmhjEgubZlhldva/wOT/OjtGzoy6L7yNKjcSadVou4VroLLK9
# qwYgKnjyzX8KEcGkKUXScwZIp8uWDp5bmKYh+5SQEa26bzHcX0a1iqmsUoP5JhYL
# xwloQM2AgY9AEAIHSFXfCo17ae/cxV3sEaLfuL09Z1sSQC5wm32hV3YyyEgsRDXE
# zXRCMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWlj
# cm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4
# MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
# QSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3Y
# bqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUB
# FDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnbo
# MlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT
# +OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuy
# e4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEh
# NSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2
# z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3
# s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78Ic
# V9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E
# 11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5P
# M4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcV
# AQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBL
# hklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggr
# BgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNS
# b29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsG
# AQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwA
# ZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0G
# CSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDB
# ZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc
# 8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYq
# wooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu
# 5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWI
# UUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXh
# j38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yH
# PgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtI
# EJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4Guzq
# N5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgR
# MiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQ
# zTGCGYswghmHAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEC
# EzMAAAMQGv99cNuNb0MAAAAAAxAwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcN
# AQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUw
# LwYJKoZIhvcNAQkEMSIEIJfh+C66Y2OKn5sSe0BedNv+jLSYOC04ZIuJUcucAXyX
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAC6+egNAHjMc5
# N6DCvkDUs5cGbqW4m96Q/ZcCxlQFCY5iujLey/gWQK049pL/ha/MIxwRRiGsmNIg
# 4wcqNrMRpcDbMcJZbPs588+5/Nj9rUau9pEc/KCLUGgEfjef/Zj5xB1thLeVWVt8
# 0SKl8xFJiczSwlDZkxrYT/CLzWSv1J+j6YF+2WD4/lLVn2fm2h8uJnSX9OGmZ5ZB
# 6bpxf2lQXPZnJ4NrllnlctiFXQd7WxtZfbaUpnfHmMJWn30G4rTpepaC5pHOq0lW
# Te8TB6i9ckevE5lP/T6bPu7y/IMuqt44KkPIlpR8wuvP3SmliZHtg892i+2ZLFar
# E2BvdpskH6GCFxUwghcRBgorBgEEAYI3AwMBMYIXATCCFv0GCSqGSIb3DQEHAqCC
# Fu4wghbqAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFYBgsqhkiG9w0BCRABBKCCAUcE
# ggFDMIIBPwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCAquLG6QIMa
# AW00nCIyN9rZCuMhFQKW5f8zaWLaSzT0pAIGYxIJsT46GBIyMDIyMDkyMDA5NTcx
# Ni43OFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMg
# TGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046OEQ0MS00QkY3LUIzQjcx
# JTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghFlMIIHFDCC
# BPygAwIBAgITMwAAAYguzcaBQeG8KgABAAABiDANBgkqhkiG9w0BAQsFADB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMTEwMjgxOTI3NDBaFw0yMzAx
# MjYxOTI3NDBaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEtNEJGNy1CM0I3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAmucQCAQmkcXHyDrV4S88VeJg2XGqNKcWpsrapRKFWchh
# jLsf/M9XN9bgznLN48BXPAtOlwoedB2kN4bZdPP3KdRNbYq1tNFUh8UnmjCCr+Cj
# LlrigHcmS0R+rsN2gBMXlLEZh2W/COuD9VOLsb2P2jDp433V4rUAAUW82M7rg81d
# 3OcctO+1XW1h3EtbQtS6QEkw6DYIuvfX7Aw8jXHZnsMugP8ZA1otprpTNUh/zRWC
# 7CJyBzymQIDSCdWhVfD4shxe+Rs61axf27bTg5H/V/SkNd9hzM6Nq/y2OjDKrLtu
# N9hS53569uhTNQeAhAVDfeHpEzlMvtXOyX6MTme3jnHdHPj6GLT9AMRIrAf96hPY
# OiPEBvHtrg6MpiI3+l6NlbSOs16/FTeljT1+sdsWGtFTZvea9pAqV1aB795aDkmZ
# 6sRm5jtdnVazfoWrHd3vDeh35WV08vW4TlOfEcV2+KbairPxaFkJ4+tlsJ+MfsVO
# iTr/ZnDgaMaHnzzogelI3AofDU9ITbMkTtTxrLPygTbRdtbptrnLzBn2jzR4TJfk
# Qo+hzWuaMu5OtMZiKV2I5MO0m1mKuUAgoq+442Lw8CQuj9EC2F8nTbJb2NcUDg+7
# 4dgJis/P8Ba/OrlxW+Trgc6TPGxCOtT739UqeslvWD6rNQ6UEO9f7vWDkhd2vtsC
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBRkebVQxKO7zru9+o27GjPljMlKSjAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQBAEFrb+1gIJsv/GKLS2zavm2ek177mk4yu6BuS6ViIuL0e20YN2ddXeiUhEdhk
# 3FRto/GD93k5SIyNJ6X+p8uQMOxI23YOSdyEzLJwh7+ftu0If8y3x6AJ0S1d12OZ
# 7fsYqljHUeccneS9DWqipHk8uM8m2ZbBhRnUN8M4iqg4roJGmZKZ9Fc8Z7ZHJgM9
# 7i7fIyA9hJH017z25WrDJlxapD5dmMyNyzzfAVqaByemCoBn4VkRCGNISx0xRlcb
# 93W6ENhJF1NBjMl3cKVEHW4d8Y0NZhpdXDteLk9HgbJyeCI2fN9GBrCS1B1ak+19
# 4PGiZKL8+gtK7NorAoAMQvFkYgrHrWCYfjV6PouC3N+A6wOBrckVOHT9PUIDK5AD
# CH4ZraQideS9LD/imKHM3I4iazPkocHcFHB9yo5d9lMJZ+pnAAWglQQjMWhUqnE/
# llA+EqjbO0lAxlmUtVioVUswhT3pK6DjFRXM/LUxwTttufz1zBjELkRIZ8uCy1Yk
# MxfBFwEos/QFIlDaFSvUn4IiWZA3VLfAEjy51iJwK2jSIHw+1bjCI+FBHcCTRH2p
# P3+h5DlQ5AZ/dvcfNrATP1wwz25Ir8KgKObHRCIYH4VI2VrmOboSHFG79JbHdkPV
# SjfLxTuTsoh5FzoU1t5urG0rwuloZZFZxTkrxfyTkhvmjDCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIICPQIBATCCAQChgdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAOE8isx8IBeVPSweD805
# l5Qdeg5CoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJ
# KoZIhvcNAQEFBQACBQDm05ndMCIYDzIwMjIwOTIwMDk0NjA1WhgPMjAyMjA5MjEw
# OTQ2MDVaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAObTmd0CAQAwBwIBAAICC0Uw
# BwIBAAICEW4wCgIFAObU610CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGE
# WQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCK
# 5hcLxygJz/B8ymO4eWufsvOWtTqrMWqxIrzdMIGQFK6jOJ0aP8jMvgYsn5bdpoSf
# 7Kci0qg2YraAvFljtAaXMeSkIpnUWa6UUnLA4qyiyHZ9m/y0YBpCgkfqMyKnBG4i
# UdJqHpuLu3U5nzt2zu12YotLir1sjO19S6wbFDyiFzGCBA0wggQJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABiC7NxoFB4bwqAAEAAAGI
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIMiEqzSwWQAt24xNTwdAiP6L/juHyv5tCnrAqrW4BtLm
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgZune7awGN0aEgvjP7JyO3NKl
# 7hstX8ChhrKmXtJJQKUwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAYguzcaBQeG8KgABAAABiDAiBCC90c/Gjm4FC311yjoyrCJ5WO7v
# V1Nvben2F7cueg/TTTANBgkqhkiG9w0BAQsFAASCAgBcR3hv+Ghiv/1U9VU5WC5w
# 8qWVWxOaw3AlXMQjZKGqEQQaUByIMiMd48Hn/CEzBtUaeoBl3AJeMlvisFTWOpty
# ngE5TIbt+YIHULYlO4DIYQUFJQXKewgGvt7RSMGSAlolM7+Dd9nDKbkJzIH+9I21
# TOTw/qsAZFsFlCwjUWonq+wwyKE6o+VylpWFmHLxT/HxBd3miMNRp+/XdCP+Ek3C
# v5YNpxS9ExcrYroqFJVywBo69envxj4INakRj4M8UnGIkEW/O3hkoG0ZrXaDe/LM
# yGeLhUbPWRGq3DiAAq9Yabz2BAYSpUKnds7lBYuTmIAFJEttfzhdBLzOn/68vKZw
# 1523KNO7OBEAuwRunR93SLekHhKB7T41KiL586vIJWSiKFARAMUhrkcdQe9dsPzX
# HoCUP7UVJPmAmH7ouyOsrtbjhQTHNIcjf8Kakz1KjP36+7lZ5eNmjfkB9tN4erFI
# XAiDlbvOv6Bl2t17hStpRL6Cr+hhTVrDMXbIgRZbgsjkd1+11MpYYMmsU5x5R4KM
# DjiH8jNmULoxakQoY5QvLi5ky/z64Uh+8wbaN4CAy9/PU4k34G6xo5LmySNu5AUB
# UOTD6ZPkLzl+b0mkDFwIECUGhBTF1dcknT5ydcILO4FVkUbUOr9+07SbZRRfYm1R
# UV2smYcu7/Pxm4DMvRr13Q==
# SIG # End signature block
