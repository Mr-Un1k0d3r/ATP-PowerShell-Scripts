param(
)
Set-Variable EXPECTED_HASH -Option Constant -Value @{
	CompressedZeekScripts = 'F3E7E9DB24E9EC904FA33FCAF4643609F2676617F148FD9BE0566A7D6054F41E'
	ZeekScripts = 'DCEE3C8DB7CB2986EFE410379EFB5932E441D8E5C1275B62F12F191E16A9B237'
}

$ErrorActionPreference = 'Stop'

$ErrorActionPreference = "Stop"
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
if (!(Test-ValidOperatingSystemArch))
{
	Write-Host 'Script cannot run on non x86 or x64 systems'
	exit 0
}

# Import first so it will reside at the top of the file.
Set-Variable ZEEK_NDR_CMDLINE_PARAMETERS -Option ReadOnly -Value "-b -C -D -i pktmon::pktmon"

Set-Variable NDR_SETUP_NAME -Option Constant -Value 'NdrSetup'
Set-Variable NDR_SETUP_EXE_NAME -Option Constant -Value ($NDR_SETUP_NAME + '.exe')
Set-Variable NDR_SETUP_PS1_NAME -Option Constant -Value  '47693a13-8e62-4bfa-93ae-f2b854a6929c.ps1'
Set-Variable SENSE_NDR_NAME -Option Constant -Value 'SenseNdr'
Set-Variable ZEEK_NDR_NAME -Option Constant -Value 'SenseNdrZ'
Set-Variable ZEEK_NDR_EXE_NAME -Option Constant -Value ($ZEEK_NDR_NAME + '.exe')
Set-Variable ZEEK_NDR_PS1_NAME -Option Constant -Value '885cf8f5-4204-4722-be85-b9cbce57bf69.ps1'

Set-Variable ZEEK_SCRIPTS_NAME -Option Constant -Value '5c23c2fb-0643-4b98-8a91-4fc6a15c67d4'
Set-Variable ZEEK_SCRIPTS_PS1_NAME -Option Constant -Value ($ZEEK_SCRIPTS_NAME + '.ps1')

Set-Variable ZEEK_SCRIPTS_ZIP_HASH_NAME -Option Constant -Value 'ZeekScripts.hash'

Set-Variable NDR_SETUP_ARG_FILE_NAME -Option Constant -Value 'NdrSetupArgs.txt'

Set-Variable ZEEK_NDR_RUNNER_RULE_NAME -Option Constant -Value 'ZeekNdrRunnerEvent'
Set-Variable EXECUTION_TIME -Option Constant -Value 21000 # 5:50 minutes
Set-Variable WATCHDOG_INTERVAL -Option Constant -Value 300 # 5 minutes

Set-Variable DEFAULT_TARGET_FOLDER -Option Constant -Value "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\SenseNDR"

Set-Variable CURRENT_VERSION -Option Constant -Value "2.4"



$ErrorActionPreference = "Stop"
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
$ErrorActionPreference = 'Stop'

# Import first so it will reside at the top of the file.


# Used for ZipFile operations.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$ErrorActionPreference = 'Stop'

$ErrorActionPreference = "Stop"

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
$LZMA_CS_725101543 = @"
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
Add-Type -TypeDefinition $LZMA_CS_725101543 -Language CSharp -IgnoreWarnings

function Compress-LZMA 
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string] $InputPath,

        [Parameter(Mandatory=$true)]
        [string] $OutputPath
    )
    [SevenZip.Compression.LZMA.LZMAAPI]::Compress($InputPath, $OutputPath)
}

function Decompress-LZMA 
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string] $InputPath,

        [Parameter(Mandatory=$true)]
        [string] $OutputPath
    )
    [SevenZip.Compression.LZMA.LZMAAPI]::Decompress($InputPath, $OutputPath)
}

function Compress-ArchiveLZMA 
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string] $InputPath,

        [Parameter(Mandatory=$true)]
        [string] $OutputPath
    )
    try
    {
        Compress-Archive $InputPath -DestinationPath "$OutputPath.zip" -CompressionLevel NoCompression -Force
        Compress-LZMA "$OutputPath.zip" $OutputPath
    }
    finally
    {
        Remove-Item "$OutputPath.zip" -Force -ErrorAction SilentlyContinue
    }
}

function Decompress-ArchiveLZMA {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string] $InputPath,

        [Parameter(Mandatory=$true)]
        [string] $OutputPath
    )
    try
    {
        Decompress-LZMA $InputPath "$InputPath.zip"
	    [System.IO.Compression.ZipFile]::ExtractToDirectory("$InputPath.zip", $OutputPath)
    }
    finally
    {
        Remove-Item "$InputPath.zip" -Force -ErrorAction SilentlyContinue
    }
}



$ErrorActionPreference = "Stop"
#------------------------------------------------------------ Common Modules  -------------------------------------------
$ErrorActionPreference = "Stop"
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

function Resolve-RelativePath 
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $BasePath,

        [Parameter(Mandatory = $true)]
        [String] $FilePath
    )
    $BasePath = (Resolve-Path $BasePath).Path
    $FullPath = (Resolve-Path $FilePath).Path
    if (!$FullPath.StartsWith($BasePath))
    {
        throw "$FilePath isn't a decendent of $BasePath"
    }
    return $FullPath.Substring($BasePath.Length + 1)
}

function Get-DirectoryHashSHA256String
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $Directory,

        [Parameter()]
        [String] $Exclude=""
    )
    $combined = ( `
        Get-ChildItem -LiteralPath $Directory -Recurse -Exclude $Exclude `
        | where { !$_.PSIsContainer } `
        | foreach { "$(Resolve-RelativePath $Directory $_.FullName)::$(Get-FileHashSHA256String $_.FullName)" }`
    ) -join ""
    return Get-StringHashSHA256 $combined
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

    [String] $FileName

    [String] ToString()
    {
        return "Failed to verify script hash of $($this.FileName). Calculated hash: $($this.CalculatedHash)"
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
            FileName = (Split-Path -Leaf $FilePath)
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

$ErrorActionPreference = 'Stop'

$ErrorActionPreference = "Stop"

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
$ErrorActionPreference = "Stop"

$GENERICEVENTDATA_CS_745857755 = @"
using System;
using System.Text;
using System.Diagnostics.Tracing;
using Microsoft.PowerShell.Commands;

[EventData] // [EventData] makes it possible to pass an instance of the class as an argument to EventSource.Write().
public class GenericEventData
{
	public String EventName { get; set; }
    public String Information { get; set; }
}
"@
Add-Type -TypeDefinition $GENERICEVENTDATA_CS_745857755 -Language CSharp -IgnoreWarnings

function Write-GenericEventData
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $RuleName,

        [Parameter(Mandatory = $true)]
        [String] $EventName,

        [Parameter(Mandatory = $true)]
        [string] $EventInformation,

        [Parameter(Mandatory = $true)]
        [Object] $EtwProvider
    )

    $eventData = New-Object GenericEventData -Property @{
        EventName   = $EventName
        Information = $EventInformation
    }

    $EtwProvider.Write($RuleName, $EventData)
}

$ZEEKNDRRUNNERETW_CS_3437677972 = @"
using System;
using System.Text;
using System.Diagnostics.Tracing;
using Microsoft.PowerShell.Commands;

[EventSource(Name = "Microsoft.Windows.SenseNdr", Guid = "001600f9-311e-5cff-2d59-ee6d065ad02b")]
public sealed class ZeekNDRRunnerEventSource : EventSource
{
    public ZeekNDRRunnerEventSource() : base(EventSourceSettings.EtwSelfDescribingEventFormat) { }
}
"@
Add-Type -TypeDefinition $ZEEKNDRRUNNERETW_CS_3437677972 -Language CSharp -IgnoreWarnings
$global:EtwProvider = [ZeekNDRRunnerEventSource]::new()

function New-Logger {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string] $Name,

		[Parameter(Mandatory = $true)]
		[string] $Version
	)
	return New-Object PSObject -Property @{
		Name = $Name
		Version = $Version
	}
}

function Write-Log
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[psobject] $Logger,

		[Parameter(Mandatory = $true)]
		[string] $Message,

		[Parameter()]
		[string] $Level="Info"
	)
	$Header = "$($Logger.Name)/$($Logger.Version)"
	$Message = "[$Level] $Message"
	$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	Write-Host "($Timestamp) $Header`: $Message"
	Write-GenericEventData -RuleName $ZEEK_NDR_RUNNER_RULE_NAME -EventName $Header -EventInformation $Message -EtwProvider $global:EtwProvider
}


Set-Variable MAX_DEPLOYMENT_RETRIES -Option Constant -Value 10
Set-Variable DEPLOYMENT_RETRY_INTERVAL_SECONDS -Option Constant -Value 5
Set-Variable DEFAULT_CATALOG_DB_GUID -Option Constant -Value "{127D0A1D-4EF2-11D1-8608-00C04FC295EE}"
Set-Variable CATALOG_PATH -Option Constant -Value "$env:SystemRoot\System32\CatRoot\$DEFAULT_CATALOG_DB_GUID\MicrosoftNdrCatalog"

$global:Deployed = $false

function Get-TargetFolder
{
	if ($DEV_MODE)
	{
		return Join-Path $PSScriptRoot ddc
	}
	return $DEFAULT_TARGET_FOLDER
}

function Get-ZeekScriptsPath
{
	return Join-Path (Get-TargetFolder) "zeek"
}

function Get-TempZeekScriptsPath
{
	return Join-Path (Get-TargetFolder) "pending_install_$(Get-Date -Format "yyyyMMddHHmmss")"
}

function Get-PendingRemovalZeekScriptsName
{
	return "pending_remove_$(Get-Date -Format "yyyyMMddHHmmss")"
}

function Wait-Condition {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [scriptblock] $Condition,

        # Time to wait for condition, in seconds.
        [Parameter(Mandatory=$true)]
        [int] $Timeout,

        # Interval between condition checks, in seconds.
        [Parameter()]
        [int] $Interval = 1
    )

    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt $Timeout) 
    {
        $conditionResult = Invoke-Command $Condition
        if ($conditionResult) 
        {
            return;
        }

        Start-Sleep -Seconds $Interval
    }
    $timer.Stop()
    throw [System.TimeoutException]::new("Timed out after waiting $Timeout seconds on Condition: $Condition.")
}

function Stop-DdcProcesses
{
	Get-Process $NDR_SETUP_NAME -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
	Get-Process $ZEEK_NDR_NAME -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Stop-ProcessIfExists
{
	param(
        [Parameter(Mandatory=$true)]
        [string] $ProcessName
    )
	Get-Process $ProcessName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Verify-SenseNdrRestarts
{
    param(
        [Parameter(Mandatory=$true)]
        [string] $SenseNdrName,

        [Parameter(Mandatory=$true)]
        [psobject] $Logger
    )
	Write-Log -Logger $Logger -Message "Waiting for $SenseNdrName to restart after scripts deployment."
	Start-Sleep -Seconds 10
	
    Write-Log -Logger $Logger -Message "Killing $SenseNdrName to force revalidation of the scripts."
	Stop-ProcessIfExists $SenseNdrName
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
		if ($null -ne $Object)
		{
			$Object.Dispose()
		}
	}
}

function Get-ReadAccessRule 
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$true)]
		[string] $SID
	)
	return [System.Security.AccessControl.FileSystemAccessRule]::new(
		(New-Object System.Security.Principal.SecurityIdentifier($SID)), 
		[System.Security.AccessControl.FileSystemRights]::Read, 
		[System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit, 
		0, 
		[System.Security.AccessControl.AccessControlType]::Allow
	)
}

function Set-ZeekScriptsAcl 
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string] $TargetDirectory
	)
	$acl = Get-Acl $TargetDirectory
	$acl.AddAccessRule((Get-ReadAccessRule -SID "S-1-5-19")) # LocalService SID
	$acl.AddAccessRule((Get-ReadAccessRule -SID "S-1-15-2-157618707-224758843-3162413466-2249835351-834486866-1672254014-2610752905")) # Container SID
	Set-Acl -AclObject $acl -Path $acl.Path
}

function Unblock-ZeekScriptsDirectory
{
	$zeekScriptsPath = Get-ZeekScriptsPath
	$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

	takeown.exe /F $zeekScriptsPath /R /D Y | Out-Null
	$acl = Get-Acl $zeekScriptsPath
	$acl.AddAccessRule(
		[System.Security.AccessControl.FileSystemAccessRule]::new(
			(New-Object System.Security.Principal.SecurityIdentifier($currentUser)), 
			[System.Security.AccessControl.FileSystemRights]::FullControl, 
			[System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit, 
			0, 
			[System.Security.AccessControl.AccessControlType]::Allow
		)
	)
	Set-Acl -AclObject $acl -Path $acl.Path
}

function Invoke-WithRetries {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$true)]
		[int] $RetryCount,

		[Parameter(Mandatory=$true)]
		[int] $RetryIntervalSeconds,
		
		[Parameter(Mandatory=$true)]
		[string] $ActionDescription,
		
		[Parameter(Mandatory=$true)]
		[scriptblock] $Action,

		[Parameter()]
		[scriptblock] $Finally
	)

	try
	{
		for ($retries = $RetryCount; $retries -gt 0; $retries -= 1)
		{
			$shouldStop, $retryReason = Invoke-Command $Action
			if ($shouldStop)
			{
				break
			}
			Start-Sleep -Seconds $RetryIntervalSeconds
		}
	}
	finally
	{
		if ($Finally)
		{
			Invoke-Command $Finally
		}
	}

	if ($retries -eq 0)
	{
		throw "Failed to $ActionDescription after $RetryCount retries due to $retryReason."
	}
}

function Disable-InheritedAuditRules
{
	param(
		[Parameter(Mandatory = $true)]
		[string] $TargetDirectory
	)

	$acl = Get-ACL -Path $TargetDirectory
	# true to protect the audit rules associated with this ObjectSecurity object from inheritance.
	# false to remove inherited audit rules.
	$acl.SetAuditRuleProtection($True, $False)
	Set-Acl -Path $TargetDirectory -AclObject $acl
}

function Deploy-ZeekScripts
{
	param(
		[Parameter(Mandatory = $true)]
		[string] $TargetDirectory,

		[Parameter(Mandatory = $true)]
		[string] $ZeekScriptsPs1FullPath,
		
		[Parameter(Mandatory = $true)]
		[string] $ZeekScriptsExpectedHash,

		[Parameter(Mandatory = $true)]
		[string] $CompressedZeekScriptsExpectedHash,

        [Parameter(Mandatory=$true)]
        [string] $SenseNdrName,
		
        [Parameter(Mandatory=$true)]
        [psobject] $Logger
	)
	if (!(Test-Path $ZeekScriptsPs1FullPath))
    {
        throw "ZeekScripts file does not exist."
    }

	Test-FileHash -FilePath $ZeekScriptsPs1FullPath -ExpectedFileHash $CompressedZeekScriptsExpectedHash
	
	$ZeekScriptsHashFullPath = Join-Path $TargetFolder $ZEEK_SCRIPTS_ZIP_HASH_NAME
	if ((Test-Path $ZeekScriptsHashFullPath) -and ($ZeekScriptsExpectedHash -eq (Get-Content $ZeekScriptsHashFullPath -ErrorAction SilentlyContinue)))
	{
		return
	}
	
	Write-Log -Logger $Logger -Message "Zeek Scripts Hash mismatch, redeploying."
	$ZeekScriptsPath = Get-ZeekScriptsPath
	$TempZeekScriptsPath = Get-TempZeekScriptsPath
	$PendingRemovalZeekScriptsName = Get-PendingRemovalZeekScriptsName
	$PendingRemovalZeekScriptsPath = (Join-Path $TargetDirectory $PendingRemovalZeekScriptsName)

	Invoke-WithRetries `
		-RetryCount $MAX_DEPLOYMENT_RETRIES `
		-RetryIntervalSeconds $DEPLOYMENT_RETRY_INTERVAL_SECONDS `
		-ActionDescription "remove previous scripts" `
		-Action `
		{
			Stop-ProcessIfExists $SenseNdrName

			if (!(Test-Path $ZeekScriptsPath))
			{
				return $true
			}

			if (Test-Path $CATALOG_PATH)
			{
				Write-Log -Logger $Logger -Level "Warning" -Message "Verification in progress, waiting for it to finish."
				return $false, "verification in progress"
			}

			try
			{
				Rename-Item -Force $ZeekScriptsPath -NewName $PendingRemovalZeekScriptsName
				Remove-Item -Force -Recurse $PendingRemovalZeekScriptsPath
				Write-Log -Logger $Logger -Message "Removed previous scripts."
				return $true
			}
			catch
			{
				Write-Log -Logger $Logger -Level "Error" -Message "Failed to remove previous scripts. Error: $($_.Exception)"
				if ($retries -eq $MAX_DEPLOYMENT_RETRIES) # on first retry
				{
					Unblock-ZeekScriptsDirectory # attempt to unblock the directory and own access to it.
				}
				return $false, "failure to remove"
			}
		} `
		-Finally `
		{
			Remove-Item -Recurse -Force $PendingRemovalZeekScriptsPath -ErrorAction SilentlyContinue
		}
	

    Write-Log -Logger $Logger -Message "Extracting Zeek scripts."
	Decompress-ArchiveLZMA $ZeekScriptsPs1FullPath $TempZeekScriptsPath

	Invoke-WithRetries `
		-RetryCount $MAX_DEPLOYMENT_RETRIES `
		-RetryIntervalSeconds $DEPLOYMENT_RETRY_INTERVAL_SECONDS `
		-ActionDescription "deploy new scripts" `
		-Action `
		{
			if (Test-Path $CATALOG_PATH)
			{
				Write-Log -Logger $Logger -Level "Warning" -Message "Verification in progress, waiting for it to finish."
				return $false, "verification in progress"
			}

			try
			{
				Move-Item -Force "$TempZeekScriptsPath\zeek" -Destination $ZeekScriptsPath
				Write-Log -Logger $Logger -Message "Deployed new scripts."
				return $true
			}
			catch
			{
				Write-Log -Logger $Logger -Level "Error" -Message "Failed to deploy new scripts. Error: $($_.Exception)"
				return $false, "failure to deploy new scripts"
			}
		} `
		-Finally `
		{
			Remove-Item -Recurse -Force $TempZeekScriptsPath -ErrorAction SilentlyContinue
		}

	Disable-InheritedAuditRules -TargetDirectory $ZeekScriptsPath

	Set-Content -LiteralPath $ZeekScriptsHashFullPath -Value $ZeekScriptsExpectedHash -NoNewline

	$global:Deployed = $true
}

function Deploy-BinaryLZMA
{
	param(
		[Parameter(Mandatory = $true)]
		[string] $TargetDirectory,
		
		[Parameter(Mandatory = $true)]
		[string] $Ps1Name,

		[Parameter(Mandatory = $true)]
		[string] $ExeName,

		[Parameter(Mandatory = $true)]
		[string] $BinaryHash,

		[Parameter(Mandatory = $true)]
		[string] $CompressedBinaryHash,
		
        [Parameter(Mandatory=$true)]
        [psobject] $Logger
	)

	$Ps1FullPath = Join-Path $PSScriptRoot $Ps1Name
	$ExeFullPath = Join-Path $TargetDirectory $ExeName
	if ((Test-Path $ExeFullPath) -and ($BinaryHash -eq (Get-FileHashSHA256String $ExeFullPath -ErrorAction SilentlyContinue )))
	{
		return
	}

	Write-Log -Logger $Logger -Message "$($ExeName) Hash mismatch. Redeploying."
	Stop-DdcProcesses
	Using-Object (Lock-File -FullPath $Ps1FullPath) {
		Test-FileHash -FilePath $Ps1FullPath -ExpectedFileHash $CompressedBinaryHash
		Decompress-LZMA $Ps1FullPath $ExeFullPath
	}

	$global:Deployed = $true
}


$ErrorActionPreference = 'Stop'


Set-Variable SENSE_NDR_PATH -Option ReadOnly -Value ("$env:ProgramFiles\Windows Defender Advanced Threat Protection\SenseNdr.exe")
Set-Variable BROKEN_SENSE_NDR_VERSION -Option ReadOnly -Value ([System.Version]::Parse("2.1.7.1"))

function Test-IsBrokenVersion 
{
    [CmdletBinding()]
    param ()
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Build -ne 22621)
    {
        return $false
    }

    if (!(Test-Path $SENSE_NDR_PATH))
    {
        return $false
    }

    $senseNdrVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($SENSE_NDR_PATH).FileVersionRaw
    if ($senseNdrVersion -gt $BROKEN_SENSE_NDR_VERSION)
    {
        return $false
    }
    
    return $true
}

function Test-IsOldSenseNdr
{
    [CmdletBinding()]
    param ()
    
    if (!(Test-Path $SENSE_NDR_PATH))
    {
        return $false
    }

    $senseNdrVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($SENSE_NDR_PATH).FileVersionRaw
    return $senseNdrVersion.Major -eq 10 # Taking the version from OS
}

$ErrorActionPreference = 'Stop'




function Clean-SenseNdrZ {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string] $TargetFolder,

        [Parameter(Mandatory=$true)]
        [psobject] $Logger
    )
    $hasCleaned = $false

    try
    {
        $processes = Get-Process -Name @($ZEEK_NDR_NAME, $NDR_SETUP_NAME) -ErrorAction SilentlyContinue
        if ($processes)
        {
            $hasCleaned = $true
        }
    
        $processes | Stop-Process -Force -ErrorAction SilentlyContinue
        $files = @(
            (Join-Path $TargetFolder $NDR_SETUP_EXE_NAME),
            (Join-Path $TargetFolder $ZEEK_NDR_EXE_NAME)
        )
        
        foreach ($file in $files)
        {
            if (Test-Path $file)
            {
                Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
                $hasCleaned = $true
            }
        }
    
        if ($hasCleaned)
        {
            Write-Log -Logger $Logger -Message "Cleaned an instance of SenseNdrZ."
        }
    }
    catch
    {
        $ErrorString = Get-SlimException $_ -WithMessage | ConvertTo-Json -Compress
        Write-Log -Logger $Logger -Level "Error" -Message "Failed to clean SenseNdrZ. Error: $ErrorString"
    }
}

$Logger = New-Logger "ZeekNDRDeployer" -Version $CURRENT_VERSION

try
{
	if ((Test-IsOldSenseNdr))
	{
		Write-Log -Logger $Logger -Message "Running alongside an old SenseNdr version, not deploying."
		exit 0
	}

	$TargetFolder = Get-TargetFolder
	if (! (Test-Path $TargetFolder -PathType Container))
	{
		mkdir $TargetFolder -Force | Out-Null
	}
	else
	{
		Clean-SenseNdrZ $TargetFolder -Logger $Logger
	}

	$ZeekScriptsPs1FullPath = Join-Path $PSScriptRoot $ZEEK_SCRIPTS_PS1_NAME
	
	Deploy-ZeekScripts -TargetDirectory $TargetFolder `
		-ZeekScriptsPs1FullPath $ZeekScriptsPs1FullPath `
		-ZeekScriptsExpectedHash $EXPECTED_HASH.ZeekScripts `
		-CompressedZeekScriptsExpectedHash $EXPECTED_HASH.CompressedZeekScripts `
		-SenseNdrName $SENSE_NDR_NAME `
		-Logger $Logger

	if ($global:Deployed)
	{
		# TODO 41145430: Remove this once the version v2.1.7.1 no longer appears on devices.
		if (Test-IsBrokenVersion)
		{
			Write-Log -Logger $Logger -Message "Running a broken version."
			Set-ZeekScriptsAcl "$TargetFolder\zeek"

			# Replace Zeek main with an empty script, which is signed by a different catalog.
			Move-Item $TargetFolder\zeek\empty\main.zeek $TargetFolder\zeek\ndr\main.zeek -Force
			Move-Item $TargetFolder\zeek\empty\scripts.cat $TargetFolder\zeek\scripts.cat -Force
		}
		Remove-Item $TargetFolder\zeek\empty -Recurse -Force
		Verify-SenseNdrRestarts $SENSE_NDR_NAME -Logger $Logger
	}

	Write-Log -Logger $Logger -Message "Finished successfully."
}
catch
{
	$ErrorString = Get-SlimException $_ -WithMessage | ConvertTo-Json -Compress
	Write-Log -Logger $Logger -Level "Error" -Message $ErrorString
	throw # Rethrowing so the exit code will be a failure and the output written to stderr.
}


# SIG # Begin signature block
# MIIntAYJKoZIhvcNAQcCoIInpTCCJ6ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA5ABFhXxNh5Oq0
# CFOeSdiy6a14SDoihU//fo1utH9/daCCDZcwggYVMIID/aADAgECAhMzAAADEBr/
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
# zTGCGXMwghlvAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEC
# EzMAAAMQGv99cNuNb0MAAAAAAxAwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcN
# AQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUw
# LwYJKoZIhvcNAQkEMSIEICPMEc733kNHI9tm+3m9R7FND4TU3Wl3Xms+6xlKGfTa
# MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAfz6KjppE28yE
# vI9FqHmypklSIJov0CvGRwYhjYfBRGYDakRZYnKs06VBybTRO7hfegUVwjGFdRnc
# Rg4NdYW/iNIbCGc6Ofexm7wdVal03eMHCoiLUmqYlpn0BoO4IAJNhUKVWSfpSGxT
# 5S3N2lTXv8tPVWEirAblWsLfWo4Vfl88gK/sDmhnrR8QytJWz7scFuS3jdB0NyTh
# QaaqANOlzGLOPEGvFQx6VRMJvVrd6nONqA+/XVj7KQTwPl8d4f+F5+R7Iit6syhQ
# KFPGMvCQYWudkeZkt2aCwp/GP1jn37hIEHquM7Cl4PKEQv1JD8n41U2DRgeDZJfW
# u7NZs7eGiaGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCC
# FtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAE
# ggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCA8FLP2US3G
# FZrU6qYlQ/k4yaiyJFVX+JO07wzE2iu8NgIGY+4+eqMgGBMyMDIzMDMxNDEzMTkz
# MS4zMzhaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgEC
# AhMzAAAByfrVjiUgdAJeAAEAAAHJMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEzOFoXDTI0MDIwMjE5MDEz
# OFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOjNFN0EtRTM1OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# 1nLi5Y5vz8K+Woxhk7qGW/vCxi5euTM01TiEbFOG8g7SFB0VMjYgo6TiRzgOQ+CN
# 53OBOKlyMHWzRL4xvaS03ZlIgetIILYiASogsEtljzElRHO7fDGDFWcdz+lCNYmJ
# oztbG3PMrnxblUHHUkr4C7EBHb2Y07Gd5GJBgP8+5AZNsTlsHGczHs45mmP7rUgc
# Mn//c8Q/GYSqdT4OXELp53h99EnyF4zcsd2ZFjxdj1lP8QGwZZS4F82JBGe2pCrS
# akyFjTxzFKUOwcQerwBR/YaQly7mtCra4PNcyEQm+n/LDce/VViQa8OM2nBZHKw6
# CyMqEzFJJy5Hizz8Z6xrqqLKti8viJUQ0FtqkTXSR3//w8PAKyBlvIYTFF/Ly3Jh
# 3cbVeOgSmubOVwv8nMehcQb2AtxcU/ldyEUqy8/thEHIWNabzHXx5O9D4btS6oJd
# gLmHxrTBtGscVQqx0z5/fUIkLE7tbwfoq84cF/URLEyw3q57KV2U4gOhc356XYEV
# QdJXo6VFWBQDYbzanQ25zY21UCkj821CyD90gqrO3rQPlcQo6erwW2DF2fsmgAbV
# qzQsz6Rkmafz4re17km7qe09PuwHw5e3x5ZIGEoVlfNnJv6+851uwKX6ApZFxPze
# Qo7W/5BtaTmkZEhwY5AdCPgPv0aaIEQn2qF7MvFwCcsCAwEAAaOCATYwggEyMB0G
# A1UdDgQWBBQFb51nRsI8ob54OhTFeVF7RC4yyzAfBgNVHSMEGDAWgBSfpxVdAF5i
# XYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQA2qLqcZt9HikIHcj7A
# lnHhjouxSjOeBaTE+EK8aXcVLm9cA8D2/ZY2OUpYvOdhuDEV9hElVmzopiJuk/xB
# Yh6dWJTRhmS7hVjrGtqzSFW0LffsRysjxkpuqyhHiBDxMXMGZ6GdzUfqVP2Zd2O+
# J/BYQJgs9NHYz/CM4XaRP+T2VM3JE1mSO1qLa+mfB427QiLj/JC7TUYgh4RY+oLM
# FVuQJZvXYl/jITFfUppJoAakBr0Vc2r1kP5DiJaNvZWJ/cuYaiWQ4k9xpw6wGz3q
# q7xAWnlGzsawwFhjtwq5EH/s37LCfehyuCw8ZRJ9W3tgSFepAVM7sUE+Pr3Uu+iP
# vBV4TsTDNFL0CVIPX+1XOJ6YRGYJ2kHGpoGc/5sgA2IKQcl97ZDYJIqixgwKNfty
# N70O0ATbpTVhsbN01FVli0H+vgcGhyzk6jpAywHPDSQ/xoEeGU4+6PFTXMRO/fMz
# GcUcf0ZHqZMm0UhoH8tOtk18k6B75KJXTtY3ZM7pTfurSv2Qrv5zzCBiyystOPw/
# IJI+k9opTgatrC39L69/KwytD0x7t0jmTXtlLZaGvoSljdyyr6QDRVkqsCaLUSSs
# AiWeav5qg64U3mLmeeko0E9TJ5yztN/jcizlHx0XsgOuN6sub3CPV7AAMMiKopdQ
# YqiPXu9IxvqXT7CE/SMC2pcNyTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkA
# AAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRl
# IEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVow
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX
# 9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1q
# UoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8d
# q6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byN
# pOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2k
# rnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4d
# Pf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgS
# Uei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8
# QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6Cm
# gyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzF
# ER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQID
# AQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQU
# KqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1
# GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0
# bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMA
# QTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbL
# j+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1p
# Y3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIz
# LmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwU
# tj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN
# 3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU
# 5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5
# KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGy
# qVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB6
# 2FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltE
# AY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFp
# AUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcd
# FYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRb
# atGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQd
# VTNYs6FwZvKhggLLMIICNAIBATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEy
# NUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAH
# BgUrDgMCGgMVAH3pi8v+HgGbjVQs4G36dRxWBt0OoIGDMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDnulnwMCIYDzIw
# MjMwMzE0MTAyNjU2WhgPMjAyMzAzMTUxMDI2NTZaMHQwOgYKKwYBBAGEWQoEATEs
# MCowCgIFAOe6WfACAQAwBwIBAAICB74wBwIBAAICEbMwCgIFAOe7q3ACAQAwNgYK
# KwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQAC
# AwGGoDANBgkqhkiG9w0BAQUFAAOBgQBYDlwshSN5hpUlVIf8uVeS/fUVkS6ezCub
# jVeFt5yvHsm1GLOMY/ndQkwrLK2Ol9tYNEB1pItPsP5HbUTgLTH+YrbIN6lnScNW
# xJ/qFk0ijt2u/t66d7MGipO0csloRj0oKoCjsliU8czhweHT5/hAI8FHy1PqlZSZ
# yhr35xPXSjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwAhMzAAAByfrVjiUgdAJeAAEAAAHJMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkq
# hkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIIdoq2nlqdO3
# uRwc5yxY3sZ47GEYTOAqlUDTUWgexipmMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB
# 5DCBvQQggXXOf1LdUUsQJ3gp2H9gDSMhiQD/zX3hXXzh2Tl2/YEwgZgwgYCkfjB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAcn61Y4lIHQCXgABAAAB
# yTAiBCC4r9F5Vjpun9ppXyRyiucjtP8V+TzLilO67HIdXx/IXTANBgkqhkiG9w0B
# AQsFAASCAgA2nmR2QG+hiX8D97apbskQ22XIIjOHDJJB1ZAbXlXhPSTrCJBkRvkS
# dZWHTp8jlNjfTNFSW3eikOktB4HoGJgdNjbpRMdoufaLKNraoFROxRQNLH9D7i62
# RaUHpi3o3dOrsFsJPDGGBdUYUwjm3xl1GC1lttxplQdyvIRGD12CcG08tP0G0BwT
# rdFTSrd0BndtF4YoT5pt85/p772hNsSUwi10xZCSr2vnD4mWB/9HZHC8LSqjX6dZ
# l8At05GWaDnct3Dnl5Rwe6puZP2NAZuhTgVWhms4N1mtjHmNr5HPGnszXHTvZf/q
# BWxJE8jn6j4AJi9wKLdkNsosDdJPNIPfS4HQpeuS/sLdlY91tc2XD+oSrcjPLVca
# GaPggNIRFy2p9LHKlo6V11Tnfhu23qR8zaVP4rwAK4zIhhSgSgUGU+ZX/mVV5syx
# uL+78felVS9hgttNgHaTUOUtMo17DDcoXjy5RwDykOYNKqnCDv6KMZQbDNi5zzip
# f2GWpdt730BAjNNzWzzY45MLRn/T3DT6Z9LIGkyRZ+o0VgHQDFgK4aGFbDDYzsEP
# dk/FInGU7ww3PooxTfITHxL+xDez02i5gvkhB2I3+01Dv6rTOKp7Sn5WXtLvHHlX
# tQrg7RNH1Fof6riEiDeOjrHyisKsYKQTc8+N4r7f76IB5cUMSuJWkA==
# SIG # End signature block
