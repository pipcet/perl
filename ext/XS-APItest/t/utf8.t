#!perl -w

use strict;
use Test::More;
$|=1;

no warnings 'deprecated'; # Some of the below are above IV_MAX on 32 bit
                          # machines, and that is tested elsewhere

use XS::APItest;
use Data::Dumper;
my $pound_sign = chr utf8::unicode_to_native(163);

sub isASCII { ord "A" == 65 }

sub display_bytes {
    use bytes;
    my $string = shift;
    return   '"'
           . join("", map { sprintf("\\x%02x", ord $_) } split "", $string)
           . '"';
}

sub output_warnings(@) {
    diag "The warnings were:\n" . join("", @_);
}

# This  test file can't use byte_utf8a_to_utf8n() from t/charset_tools.pl
# because that uses the same functions we are testing here.  So UTF-EBCDIC
# strings are hard-coded as I8 strings in this file instead, and we use array
# lookup to translate into the appropriate code page.

my @i8_to_native = (    # Only code page 1047 so far.
# _0   _1   _2   _3   _4   _5   _6   _7   _8   _9   _A   _B   _C   _D   _E   _F
0x00,0x01,0x02,0x03,0x37,0x2D,0x2E,0x2F,0x16,0x05,0x15,0x0B,0x0C,0x0D,0x0E,0x0F,
0x10,0x11,0x12,0x13,0x3C,0x3D,0x32,0x26,0x18,0x19,0x3F,0x27,0x1C,0x1D,0x1E,0x1F,
0x40,0x5A,0x7F,0x7B,0x5B,0x6C,0x50,0x7D,0x4D,0x5D,0x5C,0x4E,0x6B,0x60,0x4B,0x61,
0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0x7A,0x5E,0x4C,0x7E,0x6E,0x6F,
0x7C,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,
0xD7,0xD8,0xD9,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xAD,0xE0,0xBD,0x5F,0x6D,
0x79,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x91,0x92,0x93,0x94,0x95,0x96,
0x97,0x98,0x99,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xC0,0x4F,0xD0,0xA1,0x07,
0x20,0x21,0x22,0x23,0x24,0x25,0x06,0x17,0x28,0x29,0x2A,0x2B,0x2C,0x09,0x0A,0x1B,
0x30,0x31,0x1A,0x33,0x34,0x35,0x36,0x08,0x38,0x39,0x3A,0x3B,0x04,0x14,0x3E,0xFF,
0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x51,0x52,0x53,0x54,0x55,0x56,
0x57,0x58,0x59,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x70,0x71,0x72,0x73,
0x74,0x75,0x76,0x77,0x78,0x80,0x8A,0x8B,0x8C,0x8D,0x8E,0x8F,0x90,0x9A,0x9B,0x9C,
0x9D,0x9E,0x9F,0xA0,0xAA,0xAB,0xAC,0xAE,0xAF,0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,
0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBE,0xBF,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF,0xDA,0xDB,
0xDC,0xDD,0xDE,0xDF,0xE1,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,0xFA,0xFB,0xFC,0xFD,0xFE,
);

my @native_to_i8;
for (my $i = 0; $i < 256; $i++) {
    $native_to_i8[$i8_to_native[$i]] = $i;
}

*I8_to_native = (isASCII)
                    ? sub { return shift }
                    : sub { return join "", map { chr $i8_to_native[ord $_] }
                                            split "", shift };
*native_to_I8 = (isASCII)
                    ? sub { return shift }
                    : sub { return join "", map { chr $native_to_i8[ord $_] }
                                            split "", shift };
sub start_byte_to_cont($) {

    # Extract the code point information from the input UTF-8 start byte, and
    # return a continuation byte containing the same information.  This is
    # used in constructing an overlong malformation from valid input.

    my $byte = shift;
    my $len = test_UTF8_SKIP($byte);
    if ($len < 2) {
        die "start_byte_to_cont() is expecting a UTF-8 variant";
    }

    $byte = ord native_to_I8($byte);

    # Copied from utf8.h.  This gets rid of the leading 1 bits.
    $byte &= ((($len) >= 7) ? 0x00 : (0x1F >> (($len)-2)));

    $byte |= (isASCII) ? 0x80 : 0xA0;
    return I8_to_native(chr $byte);
}

my $is64bit = length sprintf("%x", ~0) > 8;


# Test utf8n_to_uvchr_error().  These provide essentially complete code
# coverage.  Copied from utf8.h
my $UTF8_ALLOW_EMPTY            = 0x0001;
my $UTF8_GOT_EMPTY              = $UTF8_ALLOW_EMPTY;
my $UTF8_ALLOW_CONTINUATION     = 0x0002;
my $UTF8_GOT_CONTINUATION       = $UTF8_ALLOW_CONTINUATION;
my $UTF8_ALLOW_NON_CONTINUATION = 0x0004;
my $UTF8_GOT_NON_CONTINUATION   = $UTF8_ALLOW_NON_CONTINUATION;
my $UTF8_ALLOW_SHORT            = 0x0008;
my $UTF8_GOT_SHORT              = $UTF8_ALLOW_SHORT;
my $UTF8_ALLOW_LONG             = 0x0010;
my $UTF8_GOT_LONG               = $UTF8_ALLOW_LONG;
my $UTF8_GOT_OVERFLOW           = 0x0020;
my $UTF8_DISALLOW_SURROGATE     = 0x0040;
my $UTF8_GOT_SURROGATE          = $UTF8_DISALLOW_SURROGATE;
my $UTF8_WARN_SURROGATE         = 0x0080;
my $UTF8_DISALLOW_NONCHAR       = 0x0100;
my $UTF8_GOT_NONCHAR            = $UTF8_DISALLOW_NONCHAR;
my $UTF8_WARN_NONCHAR           = 0x0200;
my $UTF8_DISALLOW_SUPER         = 0x0400;
my $UTF8_GOT_SUPER              = $UTF8_DISALLOW_SUPER;
my $UTF8_WARN_SUPER             = 0x0800;
my $UTF8_DISALLOW_ABOVE_31_BIT  = 0x1000;
my $UTF8_GOT_ABOVE_31_BIT       = $UTF8_DISALLOW_ABOVE_31_BIT;
my $UTF8_WARN_ABOVE_31_BIT      = 0x2000;
my $UTF8_CHECK_ONLY             = 0x4000;
my $UTF8_DISALLOW_ILLEGAL_C9_INTERCHANGE
                             = $UTF8_DISALLOW_SUPER|$UTF8_DISALLOW_SURROGATE;
my $UTF8_DISALLOW_ILLEGAL_INTERCHANGE
              = $UTF8_DISALLOW_ILLEGAL_C9_INTERCHANGE|$UTF8_DISALLOW_NONCHAR;
my $UTF8_WARN_ILLEGAL_C9_INTERCHANGE
                             = $UTF8_WARN_SUPER|$UTF8_WARN_SURROGATE;
my $UTF8_WARN_ILLEGAL_INTERCHANGE
              = $UTF8_WARN_ILLEGAL_C9_INTERCHANGE|$UTF8_WARN_NONCHAR;

# Test uvchr_to_utf8().
my $UNICODE_WARN_SURROGATE        = 0x0001;
my $UNICODE_WARN_NONCHAR          = 0x0002;
my $UNICODE_WARN_SUPER            = 0x0004;
my $UNICODE_WARN_ABOVE_31_BIT     = 0x0008;
my $UNICODE_DISALLOW_SURROGATE    = 0x0010;
my $UNICODE_DISALLOW_NONCHAR      = 0x0020;
my $UNICODE_DISALLOW_SUPER        = 0x0040;
my $UNICODE_DISALLOW_ABOVE_31_BIT = 0x0080;

my $look_for_everything_utf8n_to
                        = $UTF8_DISALLOW_SURROGATE
			| $UTF8_WARN_SURROGATE
			| $UTF8_DISALLOW_NONCHAR
			| $UTF8_WARN_NONCHAR
			| $UTF8_DISALLOW_SUPER
			| $UTF8_WARN_SUPER
			| $UTF8_DISALLOW_ABOVE_31_BIT
			| $UTF8_WARN_ABOVE_31_BIT;
my $look_for_everything_uvchr_to
                        = $UNICODE_DISALLOW_SURROGATE
			| $UNICODE_WARN_SURROGATE
			| $UNICODE_DISALLOW_NONCHAR
			| $UNICODE_WARN_NONCHAR
			| $UNICODE_DISALLOW_SUPER
			| $UNICODE_WARN_SUPER
			| $UNICODE_DISALLOW_ABOVE_31_BIT
			| $UNICODE_WARN_ABOVE_31_BIT;

foreach ([0, '', '', 'empty'],
	 [0, 'N', 'N', '1 char'],
	 [1, 'NN', 'N', '1 char substring'],
	 [-2, 'Perl', 'Rules', 'different'],
	 [0, $pound_sign, $pound_sign, 'pound sign'],
	 [1, $pound_sign . 10, $pound_sign . 1, '10 pounds is more than 1 pound'],
	 [1, $pound_sign . $pound_sign, $pound_sign, '2 pound signs are more than 1'],
	 [-2, ' $!', " \x{1F42B}!", 'Camels are worth more than 1 dollar'],
	 [-1, '!', "!\x{1F42A}", 'Initial substrings match'],
	) {
    my ($expect, $left, $right, $desc) = @$_;
    my $copy = $right;
    utf8::encode($copy);
    is(bytes_cmp_utf8($left, $copy), $expect, $desc);
    next if $right =~ tr/\0-\377//c;
    utf8::encode($left);
    is(bytes_cmp_utf8($right, $left), -$expect, "$desc reversed");
}

# The keys to this hash are Unicode code points, their values are the native
# UTF-8 representations of them.  The code points are chosen because they are
# "interesting" on either or both ASCII and EBCDIC platforms.  First we add
# boundaries where the number of bytes required to represent them increase, or
# are adjacent to problematic code points, so we want to make sure they aren't
# considered problematic.
my %code_points = (
    0x0100     => (isASCII) ? "\xc4\x80" : I8_to_native("\xc8\xa0"),
    0x0400 - 1 => (isASCII) ? "\xcf\xbf" : I8_to_native("\xdf\xbf"),
    0x0400     => (isASCII) ? "\xd0\x80" : I8_to_native("\xe1\xa0\xa0"),
    0x0800 - 1 => (isASCII) ? "\xdf\xbf"     : I8_to_native("\xe1\xbf\xbf"),
    0x0800     => (isASCII) ? "\xe0\xa0\x80" : I8_to_native("\xe2\xa0\xa0"),
    0x4000 - 1 => (isASCII) ? "\xe3\xbf\xbf" : I8_to_native("\xef\xbf\xbf"),
    0x4000     => (isASCII) ? "\xe4\x80\x80" : I8_to_native("\xf0\xb0\xa0\xa0"),
    0x8000 - 1 => (isASCII) ? "\xe7\xbf\xbf" : I8_to_native("\xf0\xbf\xbf\xbf"),

    # First code point that the implementation of isUTF8_POSSIBLY_PROBLEMATIC,
    # as of this writing, considers potentially problematic on EBCDIC
    0x8000     => (isASCII) ? "\xe8\x80\x80" : I8_to_native("\xf1\xa0\xa0\xa0"),

    0xD000 - 1 => (isASCII) ? "\xec\xbf\xbf" : I8_to_native("\xf1\xb3\xbf\xbf"),

    # First code point that the implementation of isUTF8_POSSIBLY_PROBLEMATIC,
    # as of this writing, considers potentially problematic on ASCII
    0xD000     => (isASCII) ? "\xed\x80\x80" : I8_to_native("\xf1\xb4\xa0\xa0"),

    # Bracket the surrogates, and include several surrogates
    0xD7FF	=> (isASCII) ? "\xed\x9f\xbf" : I8_to_native("\xf1\xb5\xbf\xbf"),
    0xD800	=> (isASCII) ? "\xed\xa0\x80" : I8_to_native("\xf1\xb6\xa0\xa0"),
    0xDC00      => (isASCII) ? "\xed\xb0\x80" : I8_to_native("\xf1\xb7\xa0\xa0"),
    0xDFFF	=> (isASCII) ? "\xee\x80\x80" : I8_to_native("\xf1\xb8\xa0\xa0"),
    0xDFFF      => (isASCII) ? "\xed\xbf\xbf" : I8_to_native("\xf1\xb7\xbf\xbf"),
    0xE000	=> (isASCII) ? "\xee\x80\x80" : I8_to_native("\xf1\xb8\xa0\xa0"),

    # Include the 32 contiguous non characters, and surrounding code points
    0xFDCF	=> (isASCII) ? "\xef\xb7\x8f" : I8_to_native("\xf1\xbf\xae\xaf"),
    0xFDD0	=> (isASCII) ? "\xef\xb7\x90" : I8_to_native("\xf1\xbf\xae\xb0"),
    0xFDD1	=> (isASCII) ? "\xef\xb7\x91" : I8_to_native("\xf1\xbf\xae\xb1"),
    0xFDD2	=> (isASCII) ? "\xef\xb7\x92" : I8_to_native("\xf1\xbf\xae\xb2"),
    0xFDD3	=> (isASCII) ? "\xef\xb7\x93" : I8_to_native("\xf1\xbf\xae\xb3"),
    0xFDD4	=> (isASCII) ? "\xef\xb7\x94" : I8_to_native("\xf1\xbf\xae\xb4"),
    0xFDD5	=> (isASCII) ? "\xef\xb7\x95" : I8_to_native("\xf1\xbf\xae\xb5"),
    0xFDD6	=> (isASCII) ? "\xef\xb7\x96" : I8_to_native("\xf1\xbf\xae\xb6"),
    0xFDD7	=> (isASCII) ? "\xef\xb7\x97" : I8_to_native("\xf1\xbf\xae\xb7"),
    0xFDD8	=> (isASCII) ? "\xef\xb7\x98" : I8_to_native("\xf1\xbf\xae\xb8"),
    0xFDD9	=> (isASCII) ? "\xef\xb7\x99" : I8_to_native("\xf1\xbf\xae\xb9"),
    0xFDDA	=> (isASCII) ? "\xef\xb7\x9a" : I8_to_native("\xf1\xbf\xae\xba"),
    0xFDDB	=> (isASCII) ? "\xef\xb7\x9b" : I8_to_native("\xf1\xbf\xae\xbb"),
    0xFDDC	=> (isASCII) ? "\xef\xb7\x9c" : I8_to_native("\xf1\xbf\xae\xbc"),
    0xFDDD	=> (isASCII) ? "\xef\xb7\x9d" : I8_to_native("\xf1\xbf\xae\xbd"),
    0xFDDE	=> (isASCII) ? "\xef\xb7\x9e" : I8_to_native("\xf1\xbf\xae\xbe"),
    0xFDDF	=> (isASCII) ? "\xef\xb7\x9f" : I8_to_native("\xf1\xbf\xae\xbf"),
    0xFDE0	=> (isASCII) ? "\xef\xb7\xa0" : I8_to_native("\xf1\xbf\xaf\xa0"),
    0xFDE1	=> (isASCII) ? "\xef\xb7\xa1" : I8_to_native("\xf1\xbf\xaf\xa1"),
    0xFDE2	=> (isASCII) ? "\xef\xb7\xa2" : I8_to_native("\xf1\xbf\xaf\xa2"),
    0xFDE3	=> (isASCII) ? "\xef\xb7\xa3" : I8_to_native("\xf1\xbf\xaf\xa3"),
    0xFDE4	=> (isASCII) ? "\xef\xb7\xa4" : I8_to_native("\xf1\xbf\xaf\xa4"),
    0xFDE5	=> (isASCII) ? "\xef\xb7\xa5" : I8_to_native("\xf1\xbf\xaf\xa5"),
    0xFDE6	=> (isASCII) ? "\xef\xb7\xa6" : I8_to_native("\xf1\xbf\xaf\xa6"),
    0xFDE7	=> (isASCII) ? "\xef\xb7\xa7" : I8_to_native("\xf1\xbf\xaf\xa7"),
    0xFDE8	=> (isASCII) ? "\xef\xb7\xa8" : I8_to_native("\xf1\xbf\xaf\xa8"),
    0xFDEa	=> (isASCII) ? "\xef\xb7\x99" : I8_to_native("\xf1\xbf\xaf\xa9"),
    0xFDEA	=> (isASCII) ? "\xef\xb7\xaa" : I8_to_native("\xf1\xbf\xaf\xaa"),
    0xFDEB	=> (isASCII) ? "\xef\xb7\xab" : I8_to_native("\xf1\xbf\xaf\xab"),
    0xFDEC	=> (isASCII) ? "\xef\xb7\xac" : I8_to_native("\xf1\xbf\xaf\xac"),
    0xFDED	=> (isASCII) ? "\xef\xb7\xad" : I8_to_native("\xf1\xbf\xaf\xad"),
    0xFDEE	=> (isASCII) ? "\xef\xb7\xae" : I8_to_native("\xf1\xbf\xaf\xae"),
    0xFDEF	=> (isASCII) ? "\xef\xb7\xaf" : I8_to_native("\xf1\xbf\xaf\xaf"),
    0xFDF0      => (isASCII) ? "\xef\xb7\xb0" : I8_to_native("\xf1\xbf\xaf\xb0"),

    # Mostly around non-characters, but some are transitions to longer strings
    0xFFFD	=> (isASCII) ? "\xef\xbf\xbd" : I8_to_native("\xf1\xbf\xbf\xbd"),
    0x10000 - 1 => (isASCII) ? "\xef\xbf\xbf" : I8_to_native("\xf1\xbf\xbf\xbf"),
    0x10000     => (isASCII) ? "\xf0\x90\x80\x80" : I8_to_native("\xf2\xa0\xa0\xa0"),
    0x1FFFD     => (isASCII) ? "\xf0\x9f\xbf\xbd" : I8_to_native("\xf3\xbf\xbf\xbd"),
    0x1FFFE     => (isASCII) ? "\xf0\x9f\xbf\xbe" : I8_to_native("\xf3\xbf\xbf\xbe"),
    0x1FFFF     => (isASCII) ? "\xf0\x9f\xbf\xbf" : I8_to_native("\xf3\xbf\xbf\xbf"),
    0x20000     => (isASCII) ? "\xf0\xa0\x80\x80" : I8_to_native("\xf4\xa0\xa0\xa0"),
    0x2FFFD     => (isASCII) ? "\xf0\xaf\xbf\xbd" : I8_to_native("\xf5\xbf\xbf\xbd"),
    0x2FFFE     => (isASCII) ? "\xf0\xaf\xbf\xbe" : I8_to_native("\xf5\xbf\xbf\xbe"),
    0x2FFFF     => (isASCII) ? "\xf0\xaf\xbf\xbf" : I8_to_native("\xf5\xbf\xbf\xbf"),
    0x30000     => (isASCII) ? "\xf0\xb0\x80\x80" : I8_to_native("\xf6\xa0\xa0\xa0"),
    0x3FFFD     => (isASCII) ? "\xf0\xbf\xbf\xbd" : I8_to_native("\xf7\xbf\xbf\xbd"),
    0x3FFFE     => (isASCII) ? "\xf0\xbf\xbf\xbe" : I8_to_native("\xf7\xbf\xbf\xbe"),
    0x40000 - 1 => (isASCII) ? "\xf0\xbf\xbf\xbf" : I8_to_native("\xf7\xbf\xbf\xbf"),
    0x40000     => (isASCII) ? "\xf1\x80\x80\x80" : I8_to_native("\xf8\xa8\xa0\xa0\xa0"),
    0x4FFFD	=> (isASCII) ? "\xf1\x8f\xbf\xbd" : I8_to_native("\xf8\xa9\xbf\xbf\xbd"),
    0x4FFFE	=> (isASCII) ? "\xf1\x8f\xbf\xbe" : I8_to_native("\xf8\xa9\xbf\xbf\xbe"),
    0x4FFFF	=> (isASCII) ? "\xf1\x8f\xbf\xbf" : I8_to_native("\xf8\xa9\xbf\xbf\xbf"),
    0x50000     => (isASCII) ? "\xf1\x90\x80\x80" : I8_to_native("\xf8\xaa\xa0\xa0\xa0"),
    0x5FFFD	=> (isASCII) ? "\xf1\x9f\xbf\xbd" : I8_to_native("\xf8\xab\xbf\xbf\xbd"),
    0x5FFFE	=> (isASCII) ? "\xf1\x9f\xbf\xbe" : I8_to_native("\xf8\xab\xbf\xbf\xbe"),
    0x5FFFF	=> (isASCII) ? "\xf1\x9f\xbf\xbf" : I8_to_native("\xf8\xab\xbf\xbf\xbf"),
    0x60000     => (isASCII) ? "\xf1\xa0\x80\x80" : I8_to_native("\xf8\xac\xa0\xa0\xa0"),
    0x6FFFD	=> (isASCII) ? "\xf1\xaf\xbf\xbd" : I8_to_native("\xf8\xad\xbf\xbf\xbd"),
    0x6FFFE	=> (isASCII) ? "\xf1\xaf\xbf\xbe" : I8_to_native("\xf8\xad\xbf\xbf\xbe"),
    0x6FFFF	=> (isASCII) ? "\xf1\xaf\xbf\xbf" : I8_to_native("\xf8\xad\xbf\xbf\xbf"),
    0x70000     => (isASCII) ? "\xf1\xb0\x80\x80" : I8_to_native("\xf8\xae\xa0\xa0\xa0"),
    0x7FFFD	=> (isASCII) ? "\xf1\xbf\xbf\xbd" : I8_to_native("\xf8\xaf\xbf\xbf\xbd"),
    0x7FFFE	=> (isASCII) ? "\xf1\xbf\xbf\xbe" : I8_to_native("\xf8\xaf\xbf\xbf\xbe"),
    0x7FFFF	=> (isASCII) ? "\xf1\xbf\xbf\xbf" : I8_to_native("\xf8\xaf\xbf\xbf\xbf"),
    0x80000     => (isASCII) ? "\xf2\x80\x80\x80" : I8_to_native("\xf8\xb0\xa0\xa0\xa0"),
    0x8FFFD	=> (isASCII) ? "\xf2\x8f\xbf\xbd" : I8_to_native("\xf8\xb1\xbf\xbf\xbd"),
    0x8FFFE	=> (isASCII) ? "\xf2\x8f\xbf\xbe" : I8_to_native("\xf8\xb1\xbf\xbf\xbe"),
    0x8FFFF	=> (isASCII) ? "\xf2\x8f\xbf\xbf" : I8_to_native("\xf8\xb1\xbf\xbf\xbf"),
    0x90000     => (isASCII) ? "\xf2\x90\x80\x80" : I8_to_native("\xf8\xb2\xa0\xa0\xa0"),
    0x9FFFD	=> (isASCII) ? "\xf2\x9f\xbf\xbd" : I8_to_native("\xf8\xb3\xbf\xbf\xbd"),
    0x9FFFE	=> (isASCII) ? "\xf2\x9f\xbf\xbe" : I8_to_native("\xf8\xb3\xbf\xbf\xbe"),
    0x9FFFF	=> (isASCII) ? "\xf2\x9f\xbf\xbf" : I8_to_native("\xf8\xb3\xbf\xbf\xbf"),
    0xA0000     => (isASCII) ? "\xf2\xa0\x80\x80" : I8_to_native("\xf8\xb4\xa0\xa0\xa0"),
    0xAFFFD	=> (isASCII) ? "\xf2\xaf\xbf\xbd" : I8_to_native("\xf8\xb5\xbf\xbf\xbd"),
    0xAFFFE	=> (isASCII) ? "\xf2\xaf\xbf\xbe" : I8_to_native("\xf8\xb5\xbf\xbf\xbe"),
    0xAFFFF	=> (isASCII) ? "\xf2\xaf\xbf\xbf" : I8_to_native("\xf8\xb5\xbf\xbf\xbf"),
    0xB0000     => (isASCII) ? "\xf2\xb0\x80\x80" : I8_to_native("\xf8\xb6\xa0\xa0\xa0"),
    0xBFFFD	=> (isASCII) ? "\xf2\xbf\xbf\xbd" : I8_to_native("\xf8\xb7\xbf\xbf\xbd"),
    0xBFFFE	=> (isASCII) ? "\xf2\xbf\xbf\xbe" : I8_to_native("\xf8\xb7\xbf\xbf\xbe"),
    0xBFFFF	=> (isASCII) ? "\xf2\xbf\xbf\xbf" : I8_to_native("\xf8\xb7\xbf\xbf\xbf"),
    0xC0000     => (isASCII) ? "\xf3\x80\x80\x80" : I8_to_native("\xf8\xb8\xa0\xa0\xa0"),
    0xCFFFD	=> (isASCII) ? "\xf3\x8f\xbf\xbd" : I8_to_native("\xf8\xb9\xbf\xbf\xbd"),
    0xCFFFE	=> (isASCII) ? "\xf3\x8f\xbf\xbe" : I8_to_native("\xf8\xb9\xbf\xbf\xbe"),
    0xCFFFF	=> (isASCII) ? "\xf3\x8f\xbf\xbf" : I8_to_native("\xf8\xb9\xbf\xbf\xbf"),
    0xD0000     => (isASCII) ? "\xf3\x90\x80\x80" : I8_to_native("\xf8\xba\xa0\xa0\xa0"),
    0xDFFFD	=> (isASCII) ? "\xf3\x9f\xbf\xbd" : I8_to_native("\xf8\xbb\xbf\xbf\xbd"),
    0xDFFFE	=> (isASCII) ? "\xf3\x9f\xbf\xbe" : I8_to_native("\xf8\xbb\xbf\xbf\xbe"),
    0xDFFFF	=> (isASCII) ? "\xf3\x9f\xbf\xbf" : I8_to_native("\xf8\xbb\xbf\xbf\xbf"),
    0xE0000     => (isASCII) ? "\xf3\xa0\x80\x80" : I8_to_native("\xf8\xbc\xa0\xa0\xa0"),
    0xEFFFD	=> (isASCII) ? "\xf3\xaf\xbf\xbd" : I8_to_native("\xf8\xbd\xbf\xbf\xbd"),
    0xEFFFE	=> (isASCII) ? "\xf3\xaf\xbf\xbe" : I8_to_native("\xf8\xbd\xbf\xbf\xbe"),
    0xEFFFF	=> (isASCII) ? "\xf3\xaf\xbf\xbf" : I8_to_native("\xf8\xbd\xbf\xbf\xbf"),
    0xF0000     => (isASCII) ? "\xf3\xb0\x80\x80" : I8_to_native("\xf8\xbe\xa0\xa0\xa0"),
    0xFFFFD	=> (isASCII) ? "\xf3\xbf\xbf\xbd" : I8_to_native("\xf8\xbf\xbf\xbf\xbd"),
    0xFFFFE	=> (isASCII) ? "\xf3\xbf\xbf\xbe" : I8_to_native("\xf8\xbf\xbf\xbf\xbe"),
    0xFFFFF	=> (isASCII) ? "\xf3\xbf\xbf\xbf" : I8_to_native("\xf8\xbf\xbf\xbf\xbf"),
    0x100000    => (isASCII) ? "\xf4\x80\x80\x80" : I8_to_native("\xf9\xa0\xa0\xa0\xa0"),
    0x10FFFD	=> (isASCII) ? "\xf4\x8f\xbf\xbd" : I8_to_native("\xf9\xa1\xbf\xbf\xbd"),
    0x10FFFE	=> (isASCII) ? "\xf4\x8f\xbf\xbe" : I8_to_native("\xf9\xa1\xbf\xbf\xbe"),
    0x10FFFF	=> (isASCII) ? "\xf4\x8f\xbf\xbf" : I8_to_native("\xf9\xa1\xbf\xbf\xbf"),
    0x110000    => (isASCII) ? "\xf4\x90\x80\x80" : I8_to_native("\xf9\xa2\xa0\xa0\xa0"),

    # Things that would be noncharacters if they were in Unicode, and might be
    # mistaken, if the C code is bad, to be nonchars
    0x11FFFE    => (isASCII) ? "\xf4\x9f\xbf\xbe" : I8_to_native("\xf9\xa3\xbf\xbf\xbe"),
    0x11FFFF    => (isASCII) ? "\xf4\x9f\xbf\xbf" : I8_to_native("\xf9\xa3\xbf\xbf\xbf"),
    0x20FFFE    => (isASCII) ? "\xf8\x88\x8f\xbf\xbe" : I8_to_native("\xfa\xa1\xbf\xbf\xbe"),
    0x20FFFF    => (isASCII) ? "\xf8\x88\x8f\xbf\xbf" : I8_to_native("\xfa\xa1\xbf\xbf\xbf"),

    0x200000 - 1 => (isASCII) ? "\xf7\xbf\xbf\xbf" : I8_to_native("\xf9\xbf\xbf\xbf\xbf"),
    0x200000     => (isASCII) ? "\xf8\x88\x80\x80\x80" : I8_to_native("\xfa\xa0\xa0\xa0\xa0"),
    0x400000 - 1 => (isASCII) ? "\xf8\x8f\xbf\xbf\xbf" : I8_to_native("\xfb\xbf\xbf\xbf\xbf"),
    0x400000     => (isASCII) ? "\xf8\x90\x80\x80\x80" : I8_to_native("\xfc\xa4\xa0\xa0\xa0\xa0"),
    0x4000000 - 1 => (isASCII) ? "\xfb\xbf\xbf\xbf\xbf" : I8_to_native("\xfd\xbf\xbf\xbf\xbf\xbf"),
    0x4000000     => (isASCII) ? "\xfc\x84\x80\x80\x80\x80" : I8_to_native("\xfe\xa2\xa0\xa0\xa0\xa0\xa0"),
    0x4000000 - 1 => (isASCII) ? "\xfb\xbf\xbf\xbf\xbf" : I8_to_native("\xfd\xbf\xbf\xbf\xbf\xbf"),
    0x4000000     => (isASCII) ? "\xfc\x84\x80\x80\x80\x80" : I8_to_native("\xfe\xa2\xa0\xa0\xa0\xa0\xa0"),
    0x40000000 - 1 => (isASCII) ? "\xfc\xbf\xbf\xbf\xbf\xbf" : I8_to_native("\xfe\xbf\xbf\xbf\xbf\xbf\xbf"),
    0x40000000     => (isASCII) ? "\xfd\x80\x80\x80\x80\x80" : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa1\xa0\xa0\xa0\xa0\xa0\xa0"),
    0x80000000 - 1 => (isASCII) ? "\xfd\xbf\xbf\xbf\xbf\xbf" : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa1\xbf\xbf\xbf\xbf\xbf\xbf"),
    0x80000000     => (isASCII) ? "\xfe\x82\x80\x80\x80\x80\x80" : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa2\xa0\xa0\xa0\xa0\xa0\xa0"),
    0xFFFFFFFF     => (isASCII) ? "\xfe\x83\xbf\xbf\xbf\xbf\xbf" : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa3\xbf\xbf\xbf\xbf\xbf\xbf"),
);

if ($is64bit) {
    no warnings qw(overflow portable);
    $code_points{0x100000000}        = (isASCII)
                                        ?              "\xfe\x84\x80\x80\x80\x80\x80"
                                        : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa4\xa0\xa0\xa0\xa0\xa0\xa0");
    $code_points{0x1000000000 - 1}   = (isASCII)
                                        ?              "\xfe\xbf\xbf\xbf\xbf\xbf\xbf"
                                        : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa1\xbf\xbf\xbf\xbf\xbf\xbf\xbf");
    $code_points{0x1000000000}       = (isASCII)
                                        ?              "\xff\x80\x80\x80\x80\x80\x81\x80\x80\x80\x80\x80\x80"
                                        : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa2\xa0\xa0\xa0\xa0\xa0\xa0\xa0");
    $code_points{0xFFFFFFFFFFFFFFFF} = (isASCII)
                                        ?              "\xff\x80\x8f\xbf\xbf\xbf\xbf\xbf\xbf\xbf\xbf\xbf\xbf"
                                        : I8_to_native("\xff\xaf\xbf\xbf\xbf\xbf\xbf\xbf\xbf\xbf\xbf\xbf\xbf\xbf");
    if (isASCII) {  # These could falsely show as overlongs in a naive implementation
        $code_points{0x40000000000}  = "\xff\x80\x80\x80\x80\x81\x80\x80\x80\x80\x80\x80\x80";
        $code_points{0x1000000000000} = "\xff\x80\x80\x80\x81\x80\x80\x80\x80\x80\x80\x80\x80";
        $code_points{0x40000000000000} = "\xff\x80\x80\x81\x80\x80\x80\x80\x80\x80\x80\x80\x80";
        $code_points{0x1000000000000000} = "\xff\x80\x81\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80";
        # overflows
        #$code_points{0xfoo}     = "\xff\x81\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80";
    }
}
elsif (! isASCII) { # 32-bit EBCDIC.  64-bit is clearer to handle, so doesn't need this test case
    no warnings qw(overflow portable);
    $code_points{0x40000000} = I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa1\xa0\xa0\xa0\xa0\xa0\xa0");
}

# Now add in entries for each of code points 0-255, which require special
# handling on EBCDIC.  Remember the keys are Unicode values, and the values
# are the native UTF-8.  For invariants, the bytes are just the native chr.

my $cp = 0;
while ($cp < ((isASCII) ? 128 : 160)) {   # This is from the definition of
                                        # invariant
    $code_points{$cp} = chr utf8::unicode_to_native($cp);
    $cp++;
}

# Done with the invariants.  Now do the variants.  All in this range are 2
# byte.  Again, we can't use the internal functions to generate UTF-8, as
# those are what we are trying to test.  In the loop, we know what range the
# continuation bytes can be in, and what the lowest start byte can be.  So we
# cycle through them.

my $first_continuation = (isASCII) ? 0x80 : 0xA0;
my $final_continuation = 0xBF;
my $start = (isASCII) ? 0xC2 : 0xC5;

my $max_bytes = (isASCII) ? 13 : 14; # Max number of bytes in a UTF-8 sequence
                                     # representing a single code point

my $continuation = $first_continuation - 1;

while ($cp < 255) {
    if (++$continuation > $final_continuation) {

        # Wrap to the next start byte when we reach the final continuation
        # byte possible
        $continuation = $first_continuation;
        $start++;
    }
    $code_points{$cp} = I8_to_native(chr($start) . chr($continuation));

    $cp++;
}

my @warnings;

use warnings 'utf8';
local $SIG{__WARN__} = sub { push @warnings, @_ };

my %restriction_types;

$restriction_types{""}{'valid_strings'} = "";
$restriction_types{"c9strict"}{'valid_strings'} = "";
$restriction_types{"strict"}{'valid_strings'} = "";
$restriction_types{"fits_in_31_bits"}{'valid_strings'} = "";

# This set of tests looks for basic sanity, and lastly tests various routines
# for the given code point.  If the earlier tests for that code point fail,
# the later ones probably will too.  Malformations are tested in later
# segments of code.
for my $u (sort { utf8::unicode_to_native($a) <=> utf8::unicode_to_native($b) }
          keys %code_points)
{
    my $hex_u = sprintf("0x%02X", $u);
    my $n = utf8::unicode_to_native($u);
    my $hex_n = sprintf("0x%02X", $n);
    my $bytes = $code_points{$u};

    my $offskip_should_be;
    {
        no warnings qw(overflow portable);
        $offskip_should_be = (isASCII)
            ? ( $u < 0x80           ? 1 :
                $u < 0x800          ? 2 :
                $u < 0x10000        ? 3 :
                $u < 0x200000       ? 4 :
                $u < 0x4000000      ? 5 :
                $u < 0x80000000     ? 6 : (($is64bit)
                                        ? ($u < 0x1000000000 ? 7 : $max_bytes)
                                        : 7)
              )
            : ($u < 0xA0        ? 1 :
               $u < 0x400       ? 2 :
               $u < 0x4000      ? 3 :
               $u < 0x40000     ? 4 :
               $u < 0x400000    ? 5 :
               $u < 0x4000000   ? 6 :
               $u < 0x40000000  ? 7 : $max_bytes );
    }

    # If this test fails, subsequent ones are meaningless.
    next unless is(test_OFFUNISKIP($u), $offskip_should_be,
                   "Verify OFFUNISKIP($hex_u) is $offskip_should_be");
    my $invariant = $offskip_should_be == 1;
    my $display_invariant = $invariant || 0;
    is(test_OFFUNI_IS_INVARIANT($u), $invariant,
       "Verify OFFUNI_IS_INVARIANT($hex_u) is $display_invariant");

    my $uvchr_skip_should_be = $offskip_should_be;
    next unless is(test_UVCHR_SKIP($n), $uvchr_skip_should_be,
                   "Verify UVCHR_SKIP($hex_n) is $uvchr_skip_should_be");
    is(test_UVCHR_IS_INVARIANT($n), $offskip_should_be == 1,
       "Verify UVCHR_IS_INVARIANT($hex_n) is $display_invariant");

    my $n_chr = chr $n;
    utf8::upgrade $n_chr;

    is(test_UTF8_SKIP($n_chr), $uvchr_skip_should_be,
        "Verify UTF8_SKIP(chr $hex_n) is $uvchr_skip_should_be");

    use bytes;
    my $byte_length = length $n_chr;
    for (my $j = 0; $j < $byte_length; $j++) {
        undef @warnings;

        if ($j == $byte_length - 1) {
            my $ret = test_is_utf8_valid_partial_char_flags($n_chr, $byte_length, 0);
            is($ret, 0, "   Verify is_utf8_valid_partial_char_flags(" . display_bytes($n_chr) . ") returns 0 for full character");
        }
        else {
            my $bytes_so_far = substr($n_chr, 0, $j + 1);
            my $ret = test_is_utf8_valid_partial_char_flags($bytes_so_far, $j + 1, 0);
            is($ret, 1, "   Verify is_utf8_valid_partial_char_flags(" . display_bytes($bytes_so_far) . ") returns 1");
        }

        unless (is(scalar @warnings, 0,
                "   Verify is_utf8_valid_partial_char_flags generated no warnings"))
        {
            output_warnings(@warnings);
        }

        my $b = substr($n_chr, $j, 1);
        my $hex_b = sprintf("\"\\x%02x\"", ord $b);

        my $byte_invariant = $j == 0 && $uvchr_skip_should_be == 1;
        my $display_byte_invariant = $byte_invariant || 0;
        next unless is(test_UTF8_IS_INVARIANT($b), $byte_invariant,
                       "   Verify UTF8_IS_INVARIANT($hex_b) for byte $j "
                     . "is $display_byte_invariant");

        my $is_start = $j == 0 && $uvchr_skip_should_be > 1;
        my $display_is_start = $is_start || 0;
        next unless is(test_UTF8_IS_START($b), $is_start,
                    "      Verify UTF8_IS_START($hex_b) is $display_is_start");

        my $is_continuation = $j != 0 && $uvchr_skip_should_be > 1;
        my $display_is_continuation = $is_continuation || 0;
        next unless is(test_UTF8_IS_CONTINUATION($b), $is_continuation,
                       "      Verify UTF8_IS_CONTINUATION($hex_b) is "
                     . "$display_is_continuation");

        my $is_continued = $uvchr_skip_should_be > 1;
        my $display_is_continued = $is_continued || 0;
        next unless is(test_UTF8_IS_CONTINUED($b), $is_continued,
                       "      Verify UTF8_IS_CONTINUED($hex_b) is "
                     . "$display_is_continued");

        my $is_downgradeable_start =    $n < 256
                                     && $uvchr_skip_should_be > 1
                                     && $j == 0;
        my $display_is_downgradeable_start = $is_downgradeable_start || 0;
        next unless is(test_UTF8_IS_DOWNGRADEABLE_START($b),
                       $is_downgradeable_start,
                       "      Verify UTF8_IS_DOWNGRADEABLE_START($hex_b) is "
                     . "$display_is_downgradeable_start");

        my $is_above_latin1 =  $n > 255 && $j == 0;
        my $display_is_above_latin1 = $is_above_latin1 || 0;
        next unless is(test_UTF8_IS_ABOVE_LATIN1($b),
                       $is_above_latin1,
                       "      Verify UTF8_IS_ABOVE_LATIN1($hex_b) is "
                     . "$display_is_above_latin1");

        my $is_possibly_problematic =  $j == 0
                                    && $n >= ((isASCII)
                                              ? 0xD000
                                              : 0x8000);
        my $display_is_possibly_problematic = $is_possibly_problematic || 0;
        next unless is(test_isUTF8_POSSIBLY_PROBLEMATIC($b),
                       $is_possibly_problematic,
                       "      Verify isUTF8_POSSIBLY_PROBLEMATIC($hex_b) is "
                     . "$display_is_above_latin1");
    }

    # We are not trying to look for warnings, etc, so if they should occur, it
    # is an error.  But some of the code points here do cause warnings, so we
    # check here and turn off the ones that apply to such code points.  A
    # later section of the code tests for these kinds of things.
    my $this_utf8_flags = $look_for_everything_utf8n_to;
    my $len = length $bytes;

    my $valid_under_strict = 1;
    my $valid_under_c9strict = 1;
    my $valid_for_fits_in_31_bits = 1;
    if ($n > 0x10FFFF) {
        $this_utf8_flags &= ~($UTF8_DISALLOW_SUPER|$UTF8_WARN_SUPER);
        $valid_under_strict = 0;
        $valid_under_c9strict = 0;
        if ($n > 2 ** 31 - 1) {
            $this_utf8_flags &=
                            ~($UTF8_DISALLOW_ABOVE_31_BIT|$UTF8_WARN_ABOVE_31_BIT);
            $valid_for_fits_in_31_bits = 0;
        }
    }
    elsif (($n >= 0xFDD0 && $n <= 0xFDEF) || ($n & 0xFFFE) == 0xFFFE) {
        $this_utf8_flags &= ~($UTF8_DISALLOW_NONCHAR|$UTF8_WARN_NONCHAR);
        $valid_under_strict = 0;
    }
    elsif ($n >= 0xD800 && $n <= 0xDFFF) {
        $this_utf8_flags &= ~($UTF8_DISALLOW_SURROGATE|$UTF8_WARN_SURROGATE);
        $valid_under_c9strict = 0;
        $valid_under_strict = 0;
    }

    undef @warnings;

    my $display_flags = sprintf "0x%x", $this_utf8_flags;
    my $display_bytes = display_bytes($bytes);
    my $ret_ref = test_utf8n_to_uvchr_error($bytes, $len, $this_utf8_flags);

    # Rest of tests likely meaningless if it gets the wrong code point.
    next unless is($ret_ref->[0], $n,
                   "Verify utf8n_to_uvchr_error($display_bytes, $display_flags)"
                 . "returns $hex_n");
    is($ret_ref->[1], $len,
       "Verify utf8n_to_uvchr_error() for $hex_n returns expected length:"
     . " $len");

    unless (is(scalar @warnings, 0,
             "Verify utf8n_to_uvchr_error() for $hex_n generated no warnings"))
    {
        output_warnings(@warnings);
    }
    is($ret_ref->[2], 0,
       "Verify utf8n_to_uvchr_error() returned no error bits");

    undef @warnings;

    my $ret = test_isUTF8_CHAR($bytes, $len);
    is($ret, $len, "Verify isUTF8_CHAR($display_bytes) returns expected length: $len");

    unless (is(scalar @warnings, 0,
               "Verify isUTF8_CHAR() for $hex_n generated no warnings"))
    {
        output_warnings(@warnings);
    }

    undef @warnings;

    $ret = test_isUTF8_CHAR($bytes, $len - 1);
    is($ret, 0, "Verify isUTF8_CHAR() with too short length parameter returns 0");

    unless (is(scalar @warnings, 0,
               "Verify isUTF8_CHAR() generated no warnings"))
    {
        output_warnings(@warnings);
    }

    undef @warnings;

    $ret = test_isUTF8_CHAR_flags($bytes, $len, 0);
    is($ret, $len, "Verify isUTF8_CHAR_flags($display_bytes, 0) returns expected length: $len");

    unless (is(scalar @warnings, 0,
               "Verify isUTF8_CHAR_flags() for $hex_n generated no warnings"))
    {
        output_warnings(@warnings);
    }

    undef @warnings;

    $ret = test_isUTF8_CHAR_flags($bytes, $len - 1, 0);
    is($ret, 0, "Verify isUTF8_CHAR_flags() with too short length parameter returns 0");

    unless (is(scalar @warnings, 0,
               "Verify isUTF8_CHAR_flags() generated no warnings"))
    {
        output_warnings(@warnings);
    }

    undef @warnings;

    $ret = test_isSTRICT_UTF8_CHAR($bytes, $len);
    my $expected_len = ($valid_under_strict) ? $len : 0;
    is($ret, $expected_len, "Verify isSTRICT_UTF8_CHAR($display_bytes) returns expected length: $expected_len");

    unless (is(scalar @warnings, 0,
               "Verify isSTRICT_UTF8_CHAR() for $hex_n generated no warnings"))
    {
        output_warnings(@warnings);
    }

    undef @warnings;

    $ret = test_isSTRICT_UTF8_CHAR($bytes, $len - 1);
    is($ret, 0, "Verify isSTRICT_UTF8_CHAR() with too short length parameter returns 0");

    unless (is(scalar @warnings, 0,
               "Verify isSTRICT_UTF8_CHAR() generated no warnings"))
    {
        output_warnings(@warnings);
    }

    undef @warnings;

    $ret = test_isUTF8_CHAR_flags($bytes, $len, $UTF8_DISALLOW_ILLEGAL_INTERCHANGE);
    is($ret, $expected_len, "Verify isUTF8_CHAR_flags('DISALLOW_ILLEGAL_INTERCHANGE') acts like isSTRICT_UTF8_CHAR");

    unless (is(scalar @warnings, 0,
               "Verify isUTF8_CHAR() for $hex_n generated no warnings"))
    {
        output_warnings(@warnings);
    }

    undef @warnings;

    $ret = test_isC9_STRICT_UTF8_CHAR($bytes, $len);
    $expected_len = ($valid_under_c9strict) ? $len : 0;
    is($ret, $expected_len, "Verify isC9_STRICT_UTF8_CHAR($display_bytes) returns expected length: $len");

    unless (is(scalar @warnings, 0,
               "Verify isC9_STRICT_UTF8_CHAR() for $hex_n generated no warnings"))
    {
        output_warnings(@warnings);
    }

    undef @warnings;

    $ret = test_isC9_STRICT_UTF8_CHAR($bytes, $len - 1);
    is($ret, 0, "Verify isC9_STRICT_UTF8_CHAR() with too short length parameter returns 0");

    unless (is(scalar @warnings, 0,
               "Verify isC9_STRICT_UTF8_CHAR() generated no warnings"))
    {
        output_warnings(@warnings);
    }

    undef @warnings;

    $ret = test_isUTF8_CHAR_flags($bytes, $len, $UTF8_DISALLOW_ILLEGAL_C9_INTERCHANGE);
    is($ret, $expected_len, "Verify isUTF8_CHAR_flags('DISALLOW_ILLEGAL_C9_INTERCHANGE') acts like isC9_STRICT_UTF8_CHAR");

    unless (is(scalar @warnings, 0,
               "Verify isUTF8_CHAR() for $hex_n generated no warnings"))
    {
        output_warnings(@warnings);
    }

    undef @warnings;

    $ret_ref = test_valid_utf8_to_uvchr($bytes);
    is($ret_ref->[0], $n, "Verify valid_utf8_to_uvchr($display_bytes) returns $hex_n");
    is($ret_ref->[1], $len, "Verify valid_utf8_to_uvchr() for $hex_n returns expected length: $len");

    unless (is(scalar @warnings, 0,
               "Verify valid_utf8_to_uvchr() for $hex_n generated no warnings"))
    {
        output_warnings(@warnings);
    }

    # Similarly for uvchr_to_utf8
    my $this_uvchr_flags = $look_for_everything_uvchr_to;
    if ($n > 2 ** 31 - 1) {
        $this_uvchr_flags &=
                ~($UNICODE_DISALLOW_ABOVE_31_BIT|$UNICODE_WARN_ABOVE_31_BIT);
    }
    if ($n > 0x10FFFF) {
        $this_uvchr_flags &= ~($UNICODE_DISALLOW_SUPER|$UNICODE_WARN_SUPER);
    }
    elsif (($n >= 0xFDD0 && $n <= 0xFDEF) || ($n & 0xFFFE) == 0xFFFE) {
        $this_uvchr_flags &= ~($UNICODE_DISALLOW_NONCHAR|$UNICODE_WARN_NONCHAR);
    }
    elsif ($n >= 0xD800 && $n <= 0xDFFF) {
        $this_uvchr_flags &= ~($UNICODE_DISALLOW_SURROGATE|$UNICODE_WARN_SURROGATE);
    }
    $display_flags = sprintf "0x%x", $this_uvchr_flags;

    undef @warnings;

    $ret = test_uvchr_to_utf8_flags($n, $this_uvchr_flags);
    ok(defined $ret, "Verify uvchr_to_utf8_flags($hex_n, $display_flags) returned success");
    is($ret, $bytes, "Verify uvchr_to_utf8_flags($hex_n, $display_flags) returns correct bytes");

    unless (is(scalar @warnings, 0,
        "Verify uvchr_to_utf8_flags($hex_n, $display_flags) for $hex_n generated no warnings"))
    {
        output_warnings(@warnings);
    }

    # Now append this code point to a string that we will test various
    # versions of is_foo_utf8_string_bar on, and keep a count of how many code
    # points are in it.  All the code points in this loop are valid in Perl's
    # extended UTF-8, but some are not valid under various restrictions.  A
    # string and count is kept separately that is entirely valid for each
    # restriction.  And, for each restriction, we note the first occurrence in
    # the unrestricted string where we find something not in the restricted
    # string.
    $restriction_types{""}{'valid_strings'} .= $bytes;
    $restriction_types{""}{'valid_counts'}++;

    if ($valid_under_c9strict) {
        $restriction_types{"c9strict"}{'valid_strings'} .= $bytes;
        $restriction_types{"c9strict"}{'valid_counts'}++;
    }
    elsif (! exists $restriction_types{"c9strict"}{'first_invalid_offset'}) {
        $restriction_types{"c9strict"}{'first_invalid_offset'}
                    = length $restriction_types{"c9strict"}{'valid_strings'};
        $restriction_types{"c9strict"}{'first_invalid_count'}
                            = $restriction_types{"c9strict"}{'valid_counts'};
    }

    if ($valid_under_strict) {
        $restriction_types{"strict"}{'valid_strings'} .= $bytes;
        $restriction_types{"strict"}{'valid_counts'}++;
    }
    elsif (! exists $restriction_types{"strict"}{'first_invalid_offset'}) {
        $restriction_types{"strict"}{'first_invalid_offset'}
                        = length $restriction_types{"strict"}{'valid_strings'};
        $restriction_types{"strict"}{'first_invalid_count'}
                                = $restriction_types{"strict"}{'valid_counts'};
    }

    if ($valid_for_fits_in_31_bits) {
        $restriction_types{"fits_in_31_bits"}{'valid_strings'} .= $bytes;
        $restriction_types{"fits_in_31_bits"}{'valid_counts'}++;
    }
    elsif (! exists
                $restriction_types{"fits_in_31_bits"}{'first_invalid_offset'})
    {
        $restriction_types{"fits_in_31_bits"}{'first_invalid_offset'}
                = length $restriction_types{"fits_in_31_bits"}{'valid_strings'};
        $restriction_types{"fits_in_31_bits"}{'first_invalid_count'}
                        = $restriction_types{"fits_in_31_bits"}{'valid_counts'};
    }
}

my $I8c = (isASCII) ? "\x80" : "\xa0";    # A continuation byte
my $cont_byte = I8_to_native($I8c);
my $p = (isASCII) ? "\xe1\x80" : I8_to_native("\xE4\xA0");  # partial

# The loop above tested the single or partial character functions/macros,
# while building up strings to test the string functions, which we do now.

for my $restriction (sort keys %restriction_types) {
    use bytes;

    for my $use_flags ("", "_flags") {

        # For each restriction, we test it in both the is_foo_flags functions
        # and the specially named foo function.  But not if there isn't such a
        # specially named function.  Currently, this is the only tested
        # restriction that doesn't have a specially named function
        next if $use_flags eq "" && $restriction eq "fits_in_31_bits";

        # Start building up the name of the function we will test.
        my $base_name = "is_";

        if (! $use_flags  && $restriction ne "") {
            $base_name .= $restriction . "_";
        }

        # We test both "is_utf8_string_foo" and "is_fixed_width_buf" functions
        foreach my $operand ('string', 'fixed_width_buf') {

            # Currently, the only fixed_width_buf functions have the '_flags'
            # suffix.
            next if $operand eq 'fixed_width_buf' && $use_flags eq "";

            my $name = "${base_name}utf8_$operand";

            # We test each version of the function
            for my $function ("_loclen", "_loc", "") {

                # We test each function against
                #   a) valid input
                #   b) invalid input created by appending an out-of-place
                #      continuation character to the valid string
                #   c) input created by appending a partial character.  This
                #      is valid in the 'fixed_width' functions, but invalid in
                #   the 'string' ones
                #   d) invalid input created by calling a function that is
                #      expecting a restricted form of the input using the string
                #      that's valid when unrestricted
                for my $error_type (0, $cont_byte, $p, $restriction) {
                    #diag "restriction=$restriction, use_flags=$use_flags, function=$function, error_type=" . display_bytes($error_type);

                    # If there is no restriction, the error type will be "",
                    # which is redundant with 0.
                    next if $error_type eq "";

                    my $this_name = "$name$function$use_flags";
                    my $bytes
                            = $restriction_types{$restriction}{'valid_strings'};
                    my $expected_offset = length $bytes;
                    my $expected_count
                            = $restriction_types{$restriction}{'valid_counts'};
                    my $test_name_suffix = "";

                    my $this_error_type = $error_type;
                    if ($this_error_type) {

                        # Appending a bare continuation byte or a partial
                        # character doesn't change the character count or
                        # offset.  But in the other cases, we have saved where
                        # the failures should occur, so use those.  Appending
                        # a continuation byte makes it invalid; appending a
                        # partial character makes the 'string' form invalid,
                        # but not the 'fixed_width_buf' form.
                        if ($this_error_type eq $cont_byte || $this_error_type eq $p) {
                            $bytes .= $this_error_type;
                            if ($this_error_type eq $cont_byte) {
                                $test_name_suffix
                                            = " for an unexpected continuation";
                            }
                            else {
                                $test_name_suffix
                                        = " if ends with a partial character";
                                $this_error_type
                                        = 0 if $operand eq "fixed_width_buf";
                            }
                        }
                        else {
                            $test_name_suffix
                                        = " if contains forbidden code points";
                            if ($this_error_type eq "c9strict") {
                                $bytes = $restriction_types{""}{'valid_strings'};
                                $expected_offset
                                 = $restriction_types{"c9strict"}
                                                     {'first_invalid_offset'};
                                $expected_count
                                  = $restriction_types{"c9strict"}
                                                      {'first_invalid_count'};
                            }
                            elsif ($this_error_type eq "strict") {
                                $bytes = $restriction_types{""}{'valid_strings'};
                                $expected_offset
                                  = $restriction_types{"strict"}
                                                      {'first_invalid_offset'};
                                $expected_count
                                  = $restriction_types{"strict"}
                                                      {'first_invalid_count'};

                            }
                            elsif ($this_error_type eq "fits_in_31_bits") {
                                $bytes = $restriction_types{""}{'valid_strings'};
                                $expected_offset
                                  = $restriction_types{"fits_in_31_bits"}
                                                      {'first_invalid_offset'};
                                $expected_count
                                    = $restriction_types{"fits_in_31_bits"}
                                                        {'first_invalid_count'};
                            }
                            else {
                                fail("Internal test error: Unknown error type "
                                . "'$this_error_type'");
                                next;
                            }
                        }
                    }

                    my $length = length $bytes;
                    my $ret_ref;

                    my $test = "\$ret_ref = test_$this_name(\$bytes, $length";

                    # If using the _flags functions, we have to figure out what
                    # flags to pass.  This is done to match the restriction.
                    if ($use_flags eq "_flags") {
                        if (! $restriction) {
                            $test .= ", 0";     # The flag

                            # Indicate the kind of flag in the test name.
                            $this_name .= "(0)";
                        }
                        else {
                            $this_name .= "($restriction)";
                            if ($restriction eq "c9strict") {
                                $test
                                  .= ", $UTF8_DISALLOW_ILLEGAL_C9_INTERCHANGE";
                            }
                            elsif ($restriction eq "strict") {
                                $test .= ", $UTF8_DISALLOW_ILLEGAL_INTERCHANGE";
                            }
                            elsif ($restriction eq "fits_in_31_bits") {
                                $test .= ", $UTF8_DISALLOW_ABOVE_31_BIT";
                            }
                            else {
                                fail("Internal test error: Unknown restriction "
                                . "'$restriction'");
                                next;
                            }
                        }
                    }
                    $test .= ")";

                    # Actually run the test
                    eval $test;
                    if ($@) {
                        fail($test);
                        diag $@;
                        next;
                    }

                    my $ret;
                    my $error_offset;
                    my $cp_count;

                    if ($function eq "") {
                        $ret = $ret_ref;    # For plain function, there's only a
                                            # single return value
                    }
                    else {  # Otherwise, the multiple values come in an array.
                        $ret = shift @$ret_ref ;
                        $error_offset = shift @$ret_ref;
                        $cp_count = shift@$ret_ref if $function eq "_loclen";
                    }

                    if ($this_error_type) {
                        is($ret, 0,
                           "Verify $this_name is FALSE$test_name_suffix");
                    }
                    else {
                        unless(is($ret, 1,
                                  "Verify $this_name is TRUE for valid input"
                                . "$test_name_suffix"))
                        {
                            diag("    The bytes starting at offset"
                               . " $error_offset are"
                               . display_bytes(substr(
                                          $restriction_types{$restriction}
                                                            {'valid_strings'},
                                          $error_offset)));
                            next;
                        }
                    }

                    if ($function ne "") {
                        unless (is($error_offset, $expected_offset,
                                   "\tAnd returns the correct offset"))
                        {
                            my $min = ($error_offset < $expected_offset)
                                    ? $error_offset
                                    : $expected_offset;
                            diag("    The bytes starting at offset" . $min
                              . " are " . display_bytes(substr($bytes, $min)));
                        }

                        if ($function eq '_loclen') {
                            is($cp_count, $expected_count,
                               "\tAnd returns the correct character count");
                        }
                    }
                }
            }
        }
    }
}

my $REPLACEMENT = 0xFFFD;

# Now test the malformations.  All these raise category utf8 warnings.
my @malformations = (
    # ($testname, $bytes, $length, $allow_flags, $expected_error_flags,
    #  $allowed_uv, $expected_len, $needed_to_discern_len, $message )
    [ "zero length string malformation", "", 0,
        $UTF8_ALLOW_EMPTY, $UTF8_GOT_EMPTY, 0, 0, 0,
        qr/empty string/
    ],
    [ "orphan continuation byte malformation", I8_to_native("${I8c}a"), 2,
        $UTF8_ALLOW_CONTINUATION, $UTF8_GOT_CONTINUATION, $REPLACEMENT,
        1, 1,
        qr/unexpected continuation byte/
    ],
    [ "premature next character malformation (immediate)",
        (isASCII) ? "\xc2\xc2\x80" : I8_to_native("\xc5\xc5\xa0"),
        3,
        $UTF8_ALLOW_NON_CONTINUATION, $UTF8_GOT_NON_CONTINUATION, $REPLACEMENT,
        1, 2,
        qr/unexpected non-continuation byte.*immediately after start byte/
    ],
    [ "premature next character malformation (non-immediate)",
        I8_to_native("\xef${I8c}a"), 3,
        $UTF8_ALLOW_NON_CONTINUATION, $UTF8_GOT_NON_CONTINUATION, $REPLACEMENT,
        2, 3,
        qr/unexpected non-continuation byte .* 2 bytes after start byte/
    ],
    [ "too short malformation", I8_to_native("\xf1${I8c}a"), 2,
        # Having the 'a' after this, but saying there are only 2 bytes also
        # tests that we pay attention to the passed in length
        $UTF8_ALLOW_SHORT, $UTF8_GOT_SHORT, $REPLACEMENT,
        2, 2,
        qr/2 bytes available, need 4/
    ],
    [ "overlong malformation, lowest 2-byte",
        (isASCII) ? "\xc0\x80" : I8_to_native("\xc0\xa0"),
        2,
        $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
        0,   # NUL
        2, 1,
        qr/overlong/
    ],
    [ "overlong malformation, highest 2-byte",
        (isASCII) ? "\xc1\xbf" : I8_to_native("\xc4\xbf"),
        2,
        $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
        (isASCII) ? 0x7F : utf8::unicode_to_native(0x9F),
        2, 1,
        qr/overlong/
    ],
    [ "overlong malformation, lowest 3-byte",
        (isASCII) ? "\xe0\x80\x80" : I8_to_native("\xe0\xa0\xa0"),
        3,
        $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
        0,   # NUL
        3, (isASCII) ? 2 : 1,
        qr/overlong/
    ],
    [ "overlong malformation, highest 3-byte",
        (isASCII) ? "\xe0\x9f\xbf" : I8_to_native("\xe0\xbf\xbf"),
        3,
        $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
        (isASCII) ? 0x7FF : 0x3FF,
        3, (isASCII) ? 2 : 1,
        qr/overlong/
    ],
    [ "overlong malformation, lowest 4-byte",
        (isASCII) ? "\xf0\x80\x80\x80" : I8_to_native("\xf0\xa0\xa0\xa0"),
        4,
        $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
        0,   # NUL
        4, 2,
        qr/overlong/
    ],
    [ "overlong malformation, highest 4-byte",
        (isASCII) ? "\xf0\x8F\xbf\xbf" : I8_to_native("\xf0\xaf\xbf\xbf"),
        4,
        $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
        (isASCII) ? 0xFFFF : 0x3FFF,
        4, 2,
        qr/overlong/
    ],
    [ "overlong malformation, lowest 5-byte",
        (isASCII)
         ?              "\xf8\x80\x80\x80\x80"
         : I8_to_native("\xf8\xa0\xa0\xa0\xa0"),
        5,
        $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
        0,   # NUL
        5, 2,
        qr/overlong/
    ],
    [ "overlong malformation, highest 5-byte",
        (isASCII)
         ?              "\xf8\x87\xbf\xbf\xbf"
         : I8_to_native("\xf8\xa7\xbf\xbf\xbf"),
        5,
        $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
        (isASCII) ? 0x1FFFFF : 0x3FFFF,
        5, 2,
        qr/overlong/
    ],
    [ "overlong malformation, lowest 6-byte",
        (isASCII)
         ?              "\xfc\x80\x80\x80\x80\x80"
         : I8_to_native("\xfc\xa0\xa0\xa0\xa0\xa0"),
        6,
        $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
        0,   # NUL
        6, 2,
        qr/overlong/
    ],
    [ "overlong malformation, highest 6-byte",
        (isASCII)
         ?              "\xfc\x83\xbf\xbf\xbf\xbf"
         : I8_to_native("\xfc\xa3\xbf\xbf\xbf\xbf"),
        6,
        $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
        (isASCII) ? 0x3FFFFFF : 0x3FFFFF,
        6, 2,
        qr/overlong/
    ],
    [ "overlong malformation, lowest 7-byte",
        (isASCII)
         ?              "\xfe\x80\x80\x80\x80\x80\x80"
         : I8_to_native("\xfe\xa0\xa0\xa0\xa0\xa0\xa0"),
        7,
        $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
        0,   # NUL
        7, 2,
        qr/overlong/
    ],
    [ "overlong malformation, highest 7-byte",
        (isASCII)
         ?              "\xfe\x81\xbf\xbf\xbf\xbf\xbf"
         : I8_to_native("\xfe\xa1\xbf\xbf\xbf\xbf\xbf"),
        7,
        $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
        (isASCII) ? 0x7FFFFFFF : 0x3FFFFFF,
        7, 2,
        qr/overlong/
    ],
);

if (isASCII && ! $is64bit) {    # 32-bit ASCII platform
    no warnings 'portable';
    push @malformations,
        [ "overflow malformation",
            "\xfe\x84\x80\x80\x80\x80\x80",  # Represents 2**32
            7,
            0,  # There is no way to allow this malformation
            $UTF8_GOT_OVERFLOW,
            $REPLACEMENT,
            7, 2,
            qr/overflows/
        ],
        [ "overflow malformation",
            "\xff\x80\x80\x80\x80\x80\x81\x80\x80\x80\x80\x80\x80",
            $max_bytes,
            0,  # There is no way to allow this malformation
            $UTF8_GOT_OVERFLOW,
            $REPLACEMENT,
            $max_bytes, 1,
            qr/overflows/
        ];
}
else { # 64-bit ASCII, or EBCDIC of any size.
    # On EBCDIC platforms, another overlong test is needed even on 32-bit
    # systems, whereas it doesn't happen on ASCII except on 64-bit ones.

    no warnings 'portable';
    no warnings 'overflow'; # Doesn't run on 32-bit systems, but compiles
    push @malformations,
        [ "overlong malformation, lowest max-byte",
            (isASCII)
             ?              "\xff\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80"
             : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"),
            $max_bytes,
            $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
            0,   # NUL
            $max_bytes, (isASCII) ? 7 : 8,
            qr/overlong/,
        ],
        [ "overlong malformation, highest max-byte",
            (isASCII)    # 2**36-1 on ASCII; 2**30-1 on EBCDIC
             ?              "\xff\x80\x80\x80\x80\x80\x80\xbf\xbf\xbf\xbf\xbf\xbf"
             : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xbf\xbf\xbf\xbf\xbf\xbf"),
            $max_bytes,
            $UTF8_ALLOW_LONG, $UTF8_GOT_LONG,
            (isASCII) ? 0xFFFFFFFFF : 0x3FFFFFFF,
            $max_bytes, (isASCII) ? 7 : 8,
            qr/overlong/,
        ];

    if (! $is64bit) {   # 32-bit EBCDIC
        push @malformations,
        [ "overflow malformation",
            I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa4\xa0\xa0\xa0\xa0\xa0\xa0"),
            $max_bytes,
            0,  # There is no way to allow this malformation
            $UTF8_GOT_OVERFLOW,
            $REPLACEMENT,
            $max_bytes, 8,
            qr/overflows/
        ];
    }
    else {  # 64-bit, either ASCII or EBCDIC
        push @malformations,
            [ "overflow malformation",
               (isASCII)
                ?              "\xff\x80\x90\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"
                : I8_to_native("\xff\xb0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"),
                $max_bytes,
                0,  # There is no way to allow this malformation
                $UTF8_GOT_OVERFLOW,
                $REPLACEMENT,
                $max_bytes, (isASCII) ? 3 : 2,
                qr/overflows/
            ];
    }
}

foreach my $test (@malformations) {
    my ($testname, $bytes, $length, $allow_flags, $expected_error_flags,
        $allowed_uv, $expected_len, $needed_to_discern_len, $message ) = @$test;

    if (length($bytes) < $length) {
        fail("Internal test error: actual buffer length (" . length($bytes)
           . ") must be at least as high as how far we are allowed to read"
           . " into it ($length)");
        diag($testname);
        next;
    }

    undef @warnings;

    my $ret = test_isUTF8_CHAR($bytes, $length);
    is($ret, 0, "$testname: isUTF8_CHAR returns 0");
    unless (is(scalar @warnings, 0,
               "$testname: isUTF8_CHAR() generated no warnings"))
    {
        output_warnings(@warnings);
    }

    undef @warnings;

    $ret = test_isUTF8_CHAR_flags($bytes, $length, 0);
    is($ret, 0, "$testname: isUTF8_CHAR_flags returns 0");
    unless (is(scalar @warnings, 0,
               "$testname: isUTF8_CHAR() generated no warnings"))
    {
        output_warnings(@warnings);
    }

    $ret = test_isSTRICT_UTF8_CHAR($bytes, $length);
    is($ret, 0, "$testname: isSTRICT_UTF8_CHAR returns 0");
    unless (is(scalar @warnings, 0,
               "$testname: isSTRICT_UTF8_CHAR() generated no warnings"))
    {
        output_warnings(@warnings);
    }

    $ret = test_isC9_STRICT_UTF8_CHAR($bytes, $length);
    is($ret, 0, "$testname: isC9_STRICT_UTF8_CHAR returns 0");
    unless (is(scalar @warnings, 0,
               "$testname: isC9_STRICT_UTF8_CHAR() generated no warnings"))
    {
        output_warnings(@warnings);
    }

    for my $j (1 .. $length - 1) {
        my $partial = substr($bytes, 0, $j);

        undef @warnings;

        $ret = test_is_utf8_valid_partial_char_flags($bytes, $j, 0);

        my $ret_should_be = 0;
        my $comment = "";
        if ($j < $needed_to_discern_len) {
            $ret_should_be = 1;
            $comment = ", but need $needed_to_discern_len bytes to discern:";
        }

        is($ret, $ret_should_be, "$testname: is_utf8_valid_partial_char_flags("
                                . display_bytes($partial)
                                . ")$comment returns $ret_should_be");
        unless (is(scalar @warnings, 0,
                "$testname: is_utf8_valid_partial_char_flags() generated no warnings"))
        {
            output_warnings(@warnings);
        }
    }


    # Test what happens when this malformation is not allowed
    undef @warnings;
    my $ret_ref = test_utf8n_to_uvchr_error($bytes, $length, 0);
    is($ret_ref->[0], 0, "$testname: disallowed: Returns 0");
    is($ret_ref->[1], $expected_len,
       "$testname: utf8n_to_uvchr_error(), disallowed: Returns expected"
     . " length: $expected_len");
    if (is(scalar @warnings, 1,
           "$testname: disallowed: Got a single warning "))
    {
        like($warnings[0], $message,
             "$testname: disallowed: Got expected warning");
    }
    else {
        if (scalar @warnings) {
            output_warnings(@warnings);
        }
    }
    is($ret_ref->[2], $expected_error_flags,
       "$testname: utf8n_to_uvchr_error(), disallowed:"
     . " Returns expected error");

    {   # Next test when disallowed, and warnings are off.
        undef @warnings;
        no warnings 'utf8';
        my $ret_ref = test_utf8n_to_uvchr_error($bytes, $length, 0);
        is($ret_ref->[0], 0,
           "$testname: utf8n_to_uvchr_error(), disallowed: no warnings 'utf8':"
         . " Returns 0");
        is($ret_ref->[1], $expected_len,
           "$testname: utf8n_to_uvchr_error(), disallowed: no warnings 'utf8':"
         . " Returns expected length: $expected_len");
        if (!is(scalar @warnings, 0,
            "$testname: utf8n_to_uvchr_error(), disallowed: no warnings 'utf8':"
          . " no warnings generated"))
        {
            output_warnings(@warnings);
        }
        is($ret_ref->[2], $expected_error_flags,
           "$testname: utf8n_to_uvchr_error(), disallowed: Returns"
         . " expected error");
    }

    # Test with CHECK_ONLY
    undef @warnings;
    $ret_ref = test_utf8n_to_uvchr_error($bytes, $length, $UTF8_CHECK_ONLY);
    is($ret_ref->[0], 0, "$testname: CHECK_ONLY: Returns 0");
    is($ret_ref->[1], -1, "$testname: CHECK_ONLY: returns -1 for length");
    if (! is(scalar @warnings, 0, "$testname: CHECK_ONLY: no warnings generated")) {
        output_warnings(@warnings);
    }
    is($ret_ref->[2], $expected_error_flags,
       "$testname: utf8n_to_uvchr_error(), disallowed: Returns expected"
     . " error");

    next if $allow_flags == 0;    # Skip if can't allow this malformation

    # Test when the malformation is allowed
    undef @warnings;
    $ret_ref = test_utf8n_to_uvchr_error($bytes, $length, $allow_flags);
    is($ret_ref->[0], $allowed_uv,
       "$testname: utf8n_to_uvchr_error(), allowed: Returns expected uv: "
     . sprintf("0x%04X", $allowed_uv));
    is($ret_ref->[1], $expected_len,
       "$testname: utf8n_to_uvchr_error(), allowed: Returns expected length:"
     . " $expected_len");
    if (!is(scalar @warnings, 0,
            "$testname: utf8n_to_uvchr_error(), allowed: no warnings"
          . " generated"))
    {
        output_warnings(@warnings);
    }
    is($ret_ref->[2], $expected_error_flags,
       "$testname: utf8n_to_uvchr_error(), disallowed: Returns"
     . " expected error");
}

sub nonportable_regex ($) {

    # Returns a pattern that matches the non-portable message raised either
    # for the specific input code point, or the one generated when there
    # is some malformation that precludes the message containing the specific
    # code point

    my $code_point = shift;

    my $string = sprintf '(Code point 0x%X is not Unicode, and'
                       . '|Any UTF-8 sequence that starts with'
                       . ' "(\\\x[[:xdigit:]]{2})+" is for a'
                       . ' non-Unicode code point, and is) not portable',
                    $code_point;
    return qr/$string/;
}

# Now test the cases where a legal code point is generated, but may or may not
# be allowed/warned on.
my @tests = (
     # ($testname, $bytes, $warn_flags, $disallow_flags, $expected_error_flags,
     #  $category, $allowed_uv, $expected_len, $needed_to_discern_len, $message )
    [ "lowest surrogate",
        (isASCII) ? "\xed\xa0\x80" : I8_to_native("\xf1\xb6\xa0\xa0"),
        $UTF8_WARN_SURROGATE, $UTF8_DISALLOW_SURROGATE, $UTF8_GOT_SURROGATE,
        'surrogate', 0xD800,
        (isASCII) ? 3 : 4,
        2,
        qr/surrogate/
    ],
    [ "a middle surrogate",
        (isASCII) ? "\xed\xa4\x8d" : I8_to_native("\xf1\xb6\xa8\xad"),
        $UTF8_WARN_SURROGATE, $UTF8_DISALLOW_SURROGATE, $UTF8_GOT_SURROGATE,
        'surrogate', 0xD90D,
        (isASCII) ? 3 : 4,
        2,
        qr/surrogate/
    ],
    [ "highest surrogate",
        (isASCII) ? "\xed\xbf\xbf" : I8_to_native("\xf1\xb7\xbf\xbf"),
        $UTF8_WARN_SURROGATE, $UTF8_DISALLOW_SURROGATE, $UTF8_GOT_SURROGATE,
        'surrogate', 0xDFFF,
        (isASCII) ? 3 : 4,
        2,
        qr/surrogate/
    ],
    [ "first non_unicode",
        (isASCII) ? "\xf4\x90\x80\x80" : I8_to_native("\xf9\xa2\xa0\xa0\xa0"),
        $UTF8_WARN_SUPER, $UTF8_DISALLOW_SUPER, $UTF8_GOT_SUPER,
        'non_unicode', 0x110000,
        (isASCII) ? 4 : 5,
        2,
        qr/(not Unicode|for a non-Unicode code point).* may not be portable/
    ],
    [ "non_unicode whose first byte tells that",
        (isASCII) ? "\xf5\x80\x80\x80" : I8_to_native("\xfa\xa0\xa0\xa0\xa0"),
        $UTF8_WARN_SUPER, $UTF8_DISALLOW_SUPER, $UTF8_GOT_SUPER,
        'non_unicode',
        (isASCII) ? 0x140000 : 0x200000,
        (isASCII) ? 4 : 5,
        1,
        qr/(not Unicode|for a non-Unicode code point).* may not be portable/
    ],
    [ "first of 32 consecutive non-character code points",
        (isASCII) ? "\xef\xb7\x90" : I8_to_native("\xf1\xbf\xae\xb0"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xFDD0,
        (isASCII) ? 3 : 4,
        (isASCII) ? 3 : 4,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "a mid non-character code point of the 32 consecutive ones",
        (isASCII) ? "\xef\xb7\xa0" : I8_to_native("\xf1\xbf\xaf\xa0"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xFDE0,
        (isASCII) ? 3 : 4,
        (isASCII) ? 3 : 4,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "final of 32 consecutive non-character code points",
        (isASCII) ? "\xef\xb7\xaf" : I8_to_native("\xf1\xbf\xaf\xaf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xFDEF,
        (isASCII) ? 3 : 4,
        (isASCII) ? 3 : 4,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+FFFE",
        (isASCII) ? "\xef\xbf\xbe" : I8_to_native("\xf1\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xFFFE,
        (isASCII) ? 3 : 4,
        (isASCII) ? 3 : 4,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+FFFF",
        (isASCII) ? "\xef\xbf\xbf" : I8_to_native("\xf1\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xFFFF,
        (isASCII) ? 3 : 4,
        (isASCII) ? 3 : 4,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+1FFFE",
        (isASCII) ? "\xf0\x9f\xbf\xbe" : I8_to_native("\xf3\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x1FFFE,
        4, 4,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+1FFFF",
        (isASCII) ? "\xf0\x9f\xbf\xbf" : I8_to_native("\xf3\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x1FFFF,
        4, 4,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+2FFFE",
        (isASCII) ? "\xf0\xaf\xbf\xbe" : I8_to_native("\xf5\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x2FFFE,
        4, 4,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+2FFFF",
        (isASCII) ? "\xf0\xaf\xbf\xbf" : I8_to_native("\xf5\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x2FFFF,
        4, 4,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+3FFFE",
        (isASCII) ? "\xf0\xbf\xbf\xbe" : I8_to_native("\xf7\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x3FFFE,
        4, 4,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+3FFFF",
        (isASCII) ? "\xf0\xbf\xbf\xbf" : I8_to_native("\xf7\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x3FFFF,
        4, 4,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+4FFFE",
        (isASCII) ? "\xf1\x8f\xbf\xbe" : I8_to_native("\xf8\xa9\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x4FFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+4FFFF",
        (isASCII) ? "\xf1\x8f\xbf\xbf" : I8_to_native("\xf8\xa9\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x4FFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+5FFFE",
        (isASCII) ? "\xf1\x9f\xbf\xbe" : I8_to_native("\xf8\xab\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x5FFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+5FFFF",
        (isASCII) ? "\xf1\x9f\xbf\xbf" : I8_to_native("\xf8\xab\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x5FFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+6FFFE",
        (isASCII) ? "\xf1\xaf\xbf\xbe" : I8_to_native("\xf8\xad\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x6FFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+6FFFF",
        (isASCII) ? "\xf1\xaf\xbf\xbf" : I8_to_native("\xf8\xad\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x6FFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+7FFFE",
        (isASCII) ? "\xf1\xbf\xbf\xbe" : I8_to_native("\xf8\xaf\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x7FFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+7FFFF",
        (isASCII) ? "\xf1\xbf\xbf\xbf" : I8_to_native("\xf8\xaf\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x7FFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+8FFFE",
        (isASCII) ? "\xf2\x8f\xbf\xbe" : I8_to_native("\xf8\xb1\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x8FFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+8FFFF",
        (isASCII) ? "\xf2\x8f\xbf\xbf" : I8_to_native("\xf8\xb1\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x8FFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+9FFFE",
        (isASCII) ? "\xf2\x9f\xbf\xbe" : I8_to_native("\xf8\xb3\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x9FFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+9FFFF",
        (isASCII) ? "\xf2\x9f\xbf\xbf" : I8_to_native("\xf8\xb3\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x9FFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+AFFFE",
        (isASCII) ? "\xf2\xaf\xbf\xbe" : I8_to_native("\xf8\xb5\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xAFFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+AFFFF",
        (isASCII) ? "\xf2\xaf\xbf\xbf" : I8_to_native("\xf8\xb5\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xAFFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+BFFFE",
        (isASCII) ? "\xf2\xbf\xbf\xbe" : I8_to_native("\xf8\xb7\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xBFFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+BFFFF",
        (isASCII) ? "\xf2\xbf\xbf\xbf" : I8_to_native("\xf8\xb7\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xBFFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+CFFFE",
        (isASCII) ? "\xf3\x8f\xbf\xbe" : I8_to_native("\xf8\xb9\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xCFFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+CFFFF",
        (isASCII) ? "\xf3\x8f\xbf\xbf" : I8_to_native("\xf8\xb9\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xCFFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+DFFFE",
        (isASCII) ? "\xf3\x9f\xbf\xbe" : I8_to_native("\xf8\xbb\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xDFFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+DFFFF",
        (isASCII) ? "\xf3\x9f\xbf\xbf" : I8_to_native("\xf8\xbb\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xDFFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+EFFFE",
        (isASCII) ? "\xf3\xaf\xbf\xbe" : I8_to_native("\xf8\xbd\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xEFFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+EFFFF",
        (isASCII) ? "\xf3\xaf\xbf\xbf" : I8_to_native("\xf8\xbd\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xEFFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+FFFFE",
        (isASCII) ? "\xf3\xbf\xbf\xbe" : I8_to_native("\xf8\xbf\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xFFFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+FFFFF",
        (isASCII) ? "\xf3\xbf\xbf\xbf" : I8_to_native("\xf8\xbf\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0xFFFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+10FFFE",
        (isASCII) ? "\xf4\x8f\xbf\xbe" : I8_to_native("\xf9\xa1\xbf\xbf\xbe"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x10FFFE,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "non-character code point U+10FFFF",
        (isASCII) ? "\xf4\x8f\xbf\xbf" : I8_to_native("\xf9\xa1\xbf\xbf\xbf"),
        $UTF8_WARN_NONCHAR, $UTF8_DISALLOW_NONCHAR, $UTF8_GOT_NONCHAR,
        'nonchar', 0x10FFFF,
        (isASCII) ? 4 : 5,
        (isASCII) ? 4 : 5,
        qr/Unicode non-character.*is not recommended for open interchange/
    ],
    [ "requires at least 32 bits",
        (isASCII)
         ? "\xfe\x82\x80\x80\x80\x80\x80"
         : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa2\xa0\xa0\xa0\xa0\xa0\xa0"),
        # This code point is chosen so that it is representable in a UV on
        # 32-bit machines
        $UTF8_WARN_ABOVE_31_BIT, $UTF8_DISALLOW_ABOVE_31_BIT,
        $UTF8_GOT_ABOVE_31_BIT,
        'utf8', 0x80000000,
        (isASCII) ? 7 : $max_bytes,
        (isASCII) ? 1 : 8,
        nonportable_regex(0x80000000)
    ],
    [ "highest 32 bit code point",
        (isASCII)
         ? "\xfe\x83\xbf\xbf\xbf\xbf\xbf"
         : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa3\xbf\xbf\xbf\xbf\xbf\xbf"),
        $UTF8_WARN_ABOVE_31_BIT, $UTF8_DISALLOW_ABOVE_31_BIT,
        $UTF8_GOT_ABOVE_31_BIT,
        'utf8', 0xFFFFFFFF,
        (isASCII) ? 7 : $max_bytes,
        (isASCII) ? 1 : 8,
        nonportable_regex(0xffffffff)
    ],
    [ "requires at least 32 bits, and use SUPER-type flags, instead of ABOVE_31_BIT",
        (isASCII)
         ? "\xfe\x82\x80\x80\x80\x80\x80"
         : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa2\xa0\xa0\xa0\xa0\xa0\xa0"),
        $UTF8_WARN_SUPER, $UTF8_DISALLOW_SUPER, $UTF8_GOT_SUPER,
        'utf8', 0x80000000,
        (isASCII) ? 7 : $max_bytes,
        (isASCII) ? 1 : 8,
        nonportable_regex(0x80000000)
    ],
    [ "overflow with warnings/disallow for more than 31 bits",
        # This tests the interaction of WARN_ABOVE_31_BIT/DISALLOW_ABOVE_31_BIT
        # with overflow.  The overflow malformation is never allowed, so
        # preventing it takes precedence if the ABOVE_31_BIT options would
        # otherwise allow in an overflowing value.  The ASCII code points (1
        # for 32-bits; 1 for 64) were chosen because the old overflow
        # detection algorithm did not catch them; this means this test also
        # checks for that fix.  The EBCDIC are arbitrary overflowing ones
        # since we have no reports of failures with it.
       (($is64bit)
        ? ((isASCII)
           ?              "\xff\x80\x90\x90\x90\xbf\xbf\xbf\xbf\xbf\xbf\xbf\xbf"
           : I8_to_native("\xff\xB0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"))
        : ((isASCII)
           ?              "\xfe\x86\x80\x80\x80\x80\x80"
           : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa0\xa4\xa0\xa0\xa0\xa0\xa0\xa0"))),
        $UTF8_WARN_ABOVE_31_BIT,
        $UTF8_DISALLOW_ABOVE_31_BIT,
        $UTF8_GOT_ABOVE_31_BIT,
        'utf8', 0,
        (! isASCII || $is64bit) ? $max_bytes : 7,
        (isASCII || $is64bit) ? 2 : 8,
        qr/overflows/
    ],
);

if (! $is64bit) {
    if (isASCII) {
        no warnings qw{portable overflow};
        push @tests,
            [ "Lowest 33 bit code point: overflow",
                "\xFE\x84\x80\x80\x80\x80\x80",
                $UTF8_WARN_ABOVE_31_BIT, $UTF8_DISALLOW_ABOVE_31_BIT,
                $UTF8_GOT_ABOVE_31_BIT,
                'utf8', 0x100000000,
                7, 1,
                qr/and( is)? not portable/
            ];
    }
}
else {
    no warnings qw{portable overflow};
    push @tests,
        [ "More than 32 bits",
            (isASCII)
            ?              "\xff\x80\x80\x80\x80\x80\x81\x80\x80\x80\x80\x80\x80"
            : I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa2\xa0\xa0\xa0\xa0\xa0\xa0\xa0"),
            $UTF8_WARN_ABOVE_31_BIT, $UTF8_DISALLOW_ABOVE_31_BIT,
            $UTF8_GOT_ABOVE_31_BIT,
            'utf8', 0x1000000000,
            $max_bytes, (isASCII) ? 1 : 7,
            qr/and( is)? not portable/
        ];
    if (! isASCII) {
        push @tests,   # These could falsely show wrongly in a naive implementation
            [ "requires at least 32 bits",
                I8_to_native("\xff\xa0\xa0\xa0\xa0\xa0\xa1\xa0\xa0\xa0\xa0\xa0\xa0\xa0"),
                $UTF8_WARN_ABOVE_31_BIT,$UTF8_DISALLOW_ABOVE_31_BIT,
                $UTF8_GOT_ABOVE_31_BIT,
                'utf8', 0x800000000,
                $max_bytes, 7,
                nonportable_regex(0x80000000)
            ],
            [ "requires at least 32 bits",
                I8_to_native("\xff\xa0\xa0\xa0\xa0\xa1\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"),
                $UTF8_WARN_ABOVE_31_BIT,$UTF8_DISALLOW_ABOVE_31_BIT,
                $UTF8_GOT_ABOVE_31_BIT,
                'utf8', 0x10000000000,
                $max_bytes, 6,
                nonportable_regex(0x10000000000)
            ],
            [ "requires at least 32 bits",
                I8_to_native("\xff\xa0\xa0\xa0\xa1\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"),
                $UTF8_WARN_ABOVE_31_BIT,$UTF8_DISALLOW_ABOVE_31_BIT,
                $UTF8_GOT_ABOVE_31_BIT,
                'utf8', 0x200000000000,
                $max_bytes, 5,
                nonportable_regex(0x20000000000)
            ],
            [ "requires at least 32 bits",
                I8_to_native("\xff\xa0\xa0\xa1\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"),
                $UTF8_WARN_ABOVE_31_BIT,$UTF8_DISALLOW_ABOVE_31_BIT,
                $UTF8_GOT_ABOVE_31_BIT,
                'utf8', 0x4000000000000,
                $max_bytes, 4,
                nonportable_regex(0x4000000000000)
            ],
            [ "requires at least 32 bits",
                I8_to_native("\xff\xa0\xa1\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"),
                $UTF8_WARN_ABOVE_31_BIT,$UTF8_DISALLOW_ABOVE_31_BIT,
                $UTF8_GOT_ABOVE_31_BIT,
                'utf8', 0x80000000000000,
                $max_bytes, 3,
                nonportable_regex(0x80000000000000)
            ],
            [ "requires at least 32 bits",
                I8_to_native("\xff\xa1\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0"),
                   #IBM-1047  \xFE\x41\x41\x41\x41\x41\x41\x43\x41\x41\x41\x41\x41\x41
                $UTF8_WARN_ABOVE_31_BIT,$UTF8_DISALLOW_ABOVE_31_BIT,
                $UTF8_GOT_ABOVE_31_BIT,
                'utf8', 0x1000000000000000,
                $max_bytes, 2,
                nonportable_regex(0x1000000000000000)
            ];
    }
}

foreach my $test (@tests) {
    my ($testname, $bytes, $warn_flags, $disallow_flags, $expected_error_flags,
        $category, $allowed_uv, $expected_len, $needed_to_discern_len, $message ) = @$test;

    my $length = length $bytes;
    my $will_overflow = $testname =~ /overflow/ ? 'overflow' : "";

    {
        use warnings;
        undef @warnings;
        my $ret = test_isUTF8_CHAR($bytes, $length);
        my $ret_flags = test_isUTF8_CHAR_flags($bytes, $length, 0);
        if ($will_overflow) {
            is($ret, 0, "isUTF8_CHAR() $testname: returns 0");
            is($ret_flags, 0, "isUTF8_CHAR_flags() $testname: returns 0");
        }
        else {
            is($ret, $length,
               "isUTF8_CHAR() $testname: returns expected length: $length");
            is($ret_flags, $length,
               "isUTF8_CHAR_flags(...,0) $testname: returns expected length: $length");
        }
        unless (is(scalar @warnings, 0,
                "isUTF8_CHAR() and isUTF8_CHAR()_flags $testname: generated no warnings"))
        {
            output_warnings(@warnings);
        }

        undef @warnings;
        $ret = test_isSTRICT_UTF8_CHAR($bytes, $length);
        if ($will_overflow) {
            is($ret, 0, "isSTRICT_UTF8_CHAR() $testname: returns 0");
        }
        else {
            my $expected_ret = (   $testname =~ /surrogate|non-character/
                                || $allowed_uv > 0x10FFFF)
                               ? 0
                               : $length;
            is($ret, $expected_ret,
               "isSTRICT_UTF8_CHAR() $testname: returns expected length: $expected_ret");
            $ret = test_isUTF8_CHAR_flags($bytes, $length,
                                          $UTF8_DISALLOW_ILLEGAL_INTERCHANGE);
            is($ret, $expected_ret,
               "isUTF8_CHAR_flags('DISALLOW_ILLEGAL_INTERCHANGE') acts like isSTRICT_UTF8_CHAR");
        }
        unless (is(scalar @warnings, 0,
                "isSTRICT_UTF8_CHAR() and isUTF8_CHAR_flags $testname: generated no warnings"))
        {
            output_warnings(@warnings);
        }

        undef @warnings;
        $ret = test_isC9_STRICT_UTF8_CHAR($bytes, $length);
        if ($will_overflow) {
            is($ret, 0, "isC9_STRICT_UTF8_CHAR() $testname: returns 0");
        }
        else {
            my $expected_ret = (   $testname =~ /surrogate/
                                || $allowed_uv > 0x10FFFF)
                               ? 0
                               : $length;
            is($ret, $expected_ret,
               "isC9_STRICT_UTF8_CHAR() $testname: returns expected length: $expected_ret");
            $ret = test_isUTF8_CHAR_flags($bytes, $length,
                                          $UTF8_DISALLOW_ILLEGAL_C9_INTERCHANGE);
            is($ret, $expected_ret,
               "isUTF8_CHAR_flags('DISALLOW_ILLEGAL_C9_INTERCHANGE') acts like isC9_STRICT_UTF8_CHAR");
        }
        unless (is(scalar @warnings, 0,
                "isC9_STRICT_UTF8_CHAR() and isUTF8_CHAR_flags $testname: generated no warnings"))
        {
            output_warnings(@warnings);
        }

        # Test partial character handling, for each byte not a full character
        for my $j (1.. $length - 1) {

            # Skip the test for the interaction between overflow and above-31
            # bit.  It is really testing other things than the partial
            # character tests, for which other tests in this file are
            # sufficient
            last if $testname =~ /overflow/;

            foreach my $disallow_flag (0, $disallow_flags) {
                my $partial = substr($bytes, 0, $j);
                my $ret_should_be;
                my $comment;
                if ($disallow_flag) {
                    $ret_should_be = 0;
                    $comment = "disallowed";
                    if ($j < $needed_to_discern_len) {
                        $ret_should_be = 1;
                        $comment .= ", but need $needed_to_discern_len bytes to discern:";
                    }
                }
                else {
                    $ret_should_be = 1;
                    $comment = "allowed";
                }

                undef @warnings;

                $ret = test_is_utf8_valid_partial_char_flags($partial, $j, $disallow_flag);
                is($ret, $ret_should_be, "$testname: is_utf8_valid_partial_char_flags("
                                        . display_bytes($partial)
                                        . "), $comment: returns $ret_should_be");
                unless (is(scalar @warnings, 0,
                        "$testname: is_utf8_valid_partial_char_flags() generated no warnings"))
                {
                    output_warnings(@warnings);
                }
            }
        }
    }

    # This is more complicated than the malformations tested earlier, as there
    # are several orthogonal variables involved.  We test all the subclasses
    # of utf8 warnings to verify they work with and without the utf8 class,
    # and don't have effects on other sublass warnings
    foreach my $warning ('utf8', 'surrogate', 'nonchar', 'non_unicode') {
      foreach my $warn_flag (0, $warn_flags) {
        foreach my $disallow_flag (0, $disallow_flags) {
          foreach my $do_warning (0, 1) {

            # We try each of the above with various combinations of
            # malformations that can occur on the same input sequence.
            foreach my $short ("", "short") {
              foreach my $unexpected_noncont ("",
                                              "unexpected non-continuation")
              {
                foreach my $overlong ("", "overlong") {

                    # If we're already at the longest possible, we
                    # can't create an overlong (which would be longer)
                    # can't handle anything larger.
                    next if $overlong && $expected_len >= $max_bytes;

                    my @malformations;
                    my @expected_errors;
                    push @malformations, $short if $short;
                    push @malformations, $unexpected_noncont
                                                      if $unexpected_noncont;
                    push @malformations, $overlong if $overlong;

                    # The overflow malformation test in the input
                    # array is coerced into being treated like one of
                    # the others.
                    if ($will_overflow) {
                        push @malformations, 'overflow';
                        push @expected_errors, $UTF8_GOT_OVERFLOW;
                    }

                    my $malformations_name = join "/", @malformations;
                    $malformations_name .= " malformation"
                                                if $malformations_name;
                    $malformations_name .= "s" if @malformations > 1;
                    my $this_bytes = $bytes;
                    my $this_length = $length;
                    my $expected_uv = $allowed_uv;
                    my $this_expected_len = $expected_len;
                    my $this_needed_to_discern_len = $needed_to_discern_len;
                    if ($malformations_name) {
                        $expected_uv = 0;

                        # Coerce the input into the desired
                        # malformation
                        if ($malformations_name =~ /overlong/) {

                            # For an overlong, we convert the original
                            # start byte into a continuation byte with
                            # the same data bits as originally. ...
                            substr($this_bytes, 0, 1)
                                = start_byte_to_cont(substr($this_bytes,
                                                            0, 1));

                            # ... Then we prepend it with a known
                            # overlong sequence.  This should evaluate
                            # to the exact same code point as the
                            # original.
                            $this_bytes
                            = I8_to_native("\xff")
                            . (I8_to_native(chr $first_continuation)
                            x ( $max_bytes - 1 - length($this_bytes)))
                            . $this_bytes;
                            $this_length = length($this_bytes);
                            $this_needed_to_discern_len
                                 = $max_bytes - ($this_expected_len
                                               - $this_needed_to_discern_len);
                            $this_expected_len = $max_bytes;
                            push @expected_errors, $UTF8_GOT_LONG;
                        }
                        if ($malformations_name =~ /short/) {

                            # Just tell the test to not look far
                            # enough into the input.
                            $this_length--;
                            $this_expected_len--;
                            push @expected_errors, $UTF8_GOT_SHORT;
                        }
                        if ($malformations_name
                                                =~ /non-continuation/)
                        {
                            # Change the final continuation byte into
                            # a non one.
                            my $pos = ($short) ? -2 : -1;
                            substr($this_bytes, $pos, 1) = '?';
                            $this_expected_len--;
                            push @expected_errors,
                                            $UTF8_GOT_NON_CONTINUATION;
                        }
                    }

                    my $eval_warn = $do_warning
                                ? "use warnings '$warning'"
                                : $warning eq "utf8"
                                    ? "no warnings 'utf8'"
                                    : ( "use warnings 'utf8';"
                                    . " no warnings '$warning'");

                    # Is effectively disallowed if we've set up a
                    # malformation, even if the flag indicates it is
                    # allowed.  Fix up test name to indicate this as
                    # well
                    my $disallowed = $disallow_flag
                                || $malformations_name;
                    my $this_name = "utf8n_to_uvchr_error() $testname: "
                                                . (($disallow_flag)
                                                ? 'disallowed'
                                                : $disallowed
                                                    ? $disallowed
                                                    : 'allowed');
                    $this_name .= ", $eval_warn";
                    $this_name .= ", " . (($warn_flag)
                                        ? 'with warning flag'
                                        : 'no warning flag');

                    undef @warnings;
                    my $ret_ref;
                    my $display_bytes = display_bytes($this_bytes);
                    my $call = "    Call was: $eval_warn; \$ret_ref"
                            . " = test_utf8n_to_uvchr_error("
                            . "'$display_bytes', $this_length,"
                            . "$warn_flag"
                            . "|$disallow_flag)";
                    my $eval_text =      "$eval_warn; \$ret_ref"
                            . " = test_utf8n_to_uvchr_error("
                            . "'$this_bytes',"
                            . " $this_length, $warn_flag"
                            . "|$disallow_flag)";
                    eval "$eval_text";
                    if (! ok ("$@ eq ''",
                        "$this_name: eval succeeded"))
                    {
                        diag "\$!='$!'; eval'd=\"$call\"";
                        next;
                    }
                    if ($disallowed) {
                        unless (is($ret_ref->[0], 0,
                                "$this_name: Returns 0"))
                        {
                            diag $call;
                        }
                    }
                    else {
                        unless (is($ret_ref->[0], $expected_uv,
                                "$this_name: Returns expected uv: "
                                . sprintf("0x%04X", $expected_uv)))
                        {
                            diag $call;
                        }
                    }
                    unless (is($ret_ref->[1], $this_expected_len,
                        "$this_name: Returns expected length:"
                    . " $this_expected_len"))
                    {
                        diag $call;
                    }

                    my $errors = $ret_ref->[2];

                    for (my $i = @expected_errors - 1; $i >= 0; $i--) {
                        if (ok($expected_errors[$i] & $errors,
                            "Expected and got error bit return"
                            . " for $malformations[$i] malformation"))
                        {
                            $errors &= ~$expected_errors[$i];
                        }
                        splice @expected_errors, $i, 1;
                    }
                    unless (is(scalar @expected_errors, 0,
                            "Got all the expected malformation errors"))
                    {
                        diag Dumper \@expected_errors;
                    }

                    if (   $this_expected_len >= $this_needed_to_discern_len
                        && ($warn_flag || $disallow_flag))
                    {
                        unless (is($errors, $expected_error_flags,
                                "Got the correct error flag"))
                        {
                            diag $call;
                        }
                    }
                    else {
                        is($errors, 0, "Got no other error flag");
                    }

                    if (@malformations) {
                        if (! $do_warning && $warning eq 'utf8') {
                            goto no_warnings_expected;
                        }

                        # Check that each malformation generates a
                        # warning, removing that warning if found
                    MALFORMATION:
                        foreach my $malformation (@malformations) {
                            foreach (my $i = 0; $i < @warnings; $i++) {
                                if ($warnings[$i] =~ /$malformation/) {
                                    pass("Expected and got"
                                    . "'$malformation' warning");
                                    splice @warnings, $i, 1;
                                    next MALFORMATION;
                                }
                            }
                            fail("Expected '$malformation' warning"
                            . " but didn't get it");

                        }
                    }

                    # Any overflow will override any super or above-31
                    # warnings.
                    goto no_warnings_expected
                                if $will_overflow || $this_expected_len
                                        < $this_needed_to_discern_len;

                    if (    ! $do_warning
                        && (   $warning eq 'utf8'
                            || $warning eq $category))
                    {
                        goto no_warnings_expected;
                    }
                    elsif ($warn_flag) {
                        if (is(scalar @warnings, 1,
                            "$this_name: Got a single warning "))
                        {
                            unless (like($warnings[0], $message,
                                    "$this_name: Got expected warning"))
                            {
                                diag $call;
                            }
                        }
                        else {
                            diag $call;
                            if (scalar @warnings) {
                                output_warnings(@warnings);
                            }
                        }
                    }
                    else {
                    no_warnings_expected:
                        unless (is(scalar @warnings, 0,
                                "$this_name: Got no warnings"))
                        {
                            diag $call;
                            output_warnings(@warnings);
                        }
                    }

                    # Check CHECK_ONLY results when the input is
                    # disallowed.  Do this when actually disallowed,
                    # not just when the $disallow_flag is set
                    if ($disallowed) {
                        undef @warnings;
                        $ret_ref = test_utf8n_to_uvchr_error(
                                    $this_bytes, $this_length,
                                    $disallow_flag|$UTF8_CHECK_ONLY);
                        unless (is($ret_ref->[0], 0,
                                "$this_name, CHECK_ONLY: Returns 0"))
                        {
                            diag $call;
                        }
                        unless (is($ret_ref->[1], -1,
                            "$this_name: CHECK_ONLY: returns -1 for"
                        . " length"))
                        {
                            diag $call;
                        }
                        if (! is(scalar @warnings, 0,
                            "$this_name, CHECK_ONLY: no warnings"
                        . " generated"))
                        {
                            diag $call;
                            output_warnings(@warnings);
                        }
                    }

                    # Now repeat some of the above, but for
                    # uvchr_to_utf8_flags().  Since this comes from an
                    # existing code point, it hasn't overflowed, and
                    # isn't malformed.
                    next if @malformations;

                    # The warning and disallow flags passed in are for
                    # utf8n_to_uvchr_error().  Convert them for
                    # uvchr_to_utf8_flags().
                    my $uvchr_warn_flag = 0;
                    my $uvchr_disallow_flag = 0;
                    if ($warn_flag) {
                        if ($warn_flag == $UTF8_WARN_SURROGATE) {
                            $uvchr_warn_flag = $UNICODE_WARN_SURROGATE
                        }
                        elsif ($warn_flag == $UTF8_WARN_NONCHAR) {
                            $uvchr_warn_flag = $UNICODE_WARN_NONCHAR
                        }
                        elsif ($warn_flag == $UTF8_WARN_SUPER) {
                            $uvchr_warn_flag = $UNICODE_WARN_SUPER
                        }
                        elsif ($warn_flag == $UTF8_WARN_ABOVE_31_BIT) {
                            $uvchr_warn_flag
                                        = $UNICODE_WARN_ABOVE_31_BIT;
                        }
                        else {
                            fail(sprintf "Unexpected warn flag: %x",
                                $warn_flag);
                            next;
                        }
                    }
                    if ($disallow_flag) {
                        if ($disallow_flag == $UTF8_DISALLOW_SURROGATE)
                        {
                            $uvchr_disallow_flag
                                        = $UNICODE_DISALLOW_SURROGATE;
                        }
                        elsif ($disallow_flag == $UTF8_DISALLOW_NONCHAR)
                        {
                            $uvchr_disallow_flag
                                        = $UNICODE_DISALLOW_NONCHAR;
                        }
                        elsif ($disallow_flag == $UTF8_DISALLOW_SUPER) {
                            $uvchr_disallow_flag
                                        = $UNICODE_DISALLOW_SUPER;
                        }
                        elsif ($disallow_flag
                                        == $UTF8_DISALLOW_ABOVE_31_BIT)
                        {
                            $uvchr_disallow_flag =
                                        $UNICODE_DISALLOW_ABOVE_31_BIT;
                        }
                        else {
                            fail(sprintf "Unexpected disallow flag: %x",
                                $disallow_flag);
                            next;
                        }
                    }

                    $disallowed = $uvchr_disallow_flag;

                    $this_name = "uvchr_to_utf8_flags() $testname: "
                                            . (($uvchr_disallow_flag)
                                                ? 'disallowed'
                                                : ($disallowed)
                                                ? 'ABOVE_31_BIT allowed'
                                                : 'allowed');
                    $this_name .= ", $eval_warn";
                    $this_name .= ", " . (($uvchr_warn_flag)
                                        ? 'with warning flag'
                                        : 'no warning flag');

                    undef @warnings;
                    my $ret;
                    my $warn_flag = sprintf "0x%x", $uvchr_warn_flag;
                    my $disallow_flag = sprintf "0x%x",
                                                $uvchr_disallow_flag;
                    $call = sprintf("    Call was: $eval_warn; \$ret"
                                . " = test_uvchr_to_utf8_flags("
                                . " 0x%x, $warn_flag|$disallow_flag)",
                                $allowed_uv);
                    $eval_text = "$eval_warn; \$ret ="
                            . " test_uvchr_to_utf8_flags("
                            . "$allowed_uv, $warn_flag|"
                            . "$disallow_flag)";
                    eval "$eval_text";
                    if (! ok ("$@ eq ''", "$this_name: eval succeeded"))
                    {
                        diag "\$!='$!'; eval'd=\"$eval_text\"";
                        next;
                    }
                    if ($disallowed) {
                        unless (is($ret, undef,
                                "$this_name: Returns undef"))
                        {
                            diag $call;
                        }
                    }
                    else {
                        unless (is($ret, $bytes,
                                "$this_name: Returns expected string"))
                        {
                            diag $call;
                        }
                    }
                    if (! $do_warning
                        && ($warning eq 'utf8' || $warning eq $category))
                    {
                        if (!is(scalar @warnings, 0,
                                "$this_name: No warnings generated"))
                        {
                            diag $call;
                            output_warnings(@warnings);
                        }
                    }
                    elsif (       $uvchr_warn_flag
                        && (   $warning eq 'utf8'
                            || $warning eq $category))
                    {
                        if (is(scalar @warnings, 1,
                            "$this_name: Got a single warning "))
                        {
                            unless (like($warnings[0], $message,
                                    "$this_name: Got expected warning"))
                            {
                                diag $call;
                            }
                        }
                        else {
                            diag $call;
                            output_warnings(@warnings)
                                                if scalar @warnings;
                        }
                    }
                }
              }
            }
          }
        }
      }
    }
}

SKIP:
{
    isASCII
      or skip "These tests probably break on non-ASCII", 1;
    my $simple = join "", "A" .. "J";
    my $utf_ch = "\x{7fffffff}";
    utf8::encode($utf_ch);
    my $utf_ch_len = length $utf_ch;
    note "utf_ch_len $utf_ch_len";
    my $utf = $utf_ch x 10;
    my $bad_start = substr($utf, 1);
    # $bad_end ends with a start byte and a single continuation
    my $bad_end = substr($utf, 0, length($utf)-$utf_ch_len+2);

    # WARNING: all offsets are *byte* offsets
    my @hop_tests =
      (
       # string      s                off        expected         name
       [ $simple,    0,               5,         5,               "simple in range, forward" ],
       [ $simple,    10,              -5,        5,               "simple in range, backward" ],
       [ $simple,    5,               10,        10,              "simple out of range, forward" ],
       [ $simple,    5,               -10,       0,               "simple out of range, backward" ],
       [ $utf,       $utf_ch_len * 5, 5,         length($utf),    "utf in range, forward" ],
       [ $utf,       $utf_ch_len * 5, -5,        0,               "utf in range, backward" ],
       [ $utf,       $utf_ch_len * 5, 4,         $utf_ch_len * 9, "utf in range b, forward" ],
       [ $utf,       $utf_ch_len * 5, -4,        $utf_ch_len,     "utf in range b, backward" ],
       [ $utf,       $utf_ch_len * 5, 6,         length($utf),    "utf out of range, forward" ],
       [ $utf,       $utf_ch_len * 5, -6,        0,               "utf out of range, backward"  ],
       [ $bad_start, 0,               1,         1,               "bad start, forward 1 from 0" ],
       [ $bad_start, 0,               $utf_ch_len-1, $utf_ch_len-1, "bad start, forward ch_len-1 from 0" ],
       [ $bad_start, 0,               $utf_ch_len, $utf_ch_len*2-1, "bad start, forward ch_len from 0" ],
       [ $bad_start, $utf_ch_len-1,   -1,        0,                "bad start, back 1 from first start byte" ],
       [ $bad_start, $utf_ch_len-2,   -1,        0,                "bad start, back 1 from before first start byte" ],
       [ $bad_start, 0,               -1,        0,                "bad start, back 1 from 0" ],
       [ $bad_start, length $bad_start, -10,     0,                "bad start, back 10 from end" ],
       [ $bad_end,   0,               10,        length $bad_end, "bad end, forward 10 from 0" ],
       [ $bad_end,   length($bad_end)-1, 10,     length $bad_end, "bad end, forward 1 from end-1" ],
       );

    for my $test (@hop_tests) {
        my ($str, $s_off, $off, $want, $name) = @$test;
        my $result = test_utf8_hop_safe($str, $s_off, $off);
        is($result, $want, "utf8_hop_safe: $name");
    }
}

done_testing;
