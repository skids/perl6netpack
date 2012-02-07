use v6;
BEGIN { @*INC.unshift: './lib'; }

use IPv4::Grammar;
use Test;

plan 71;

my grammar Lasthex is IPv4::Grammar::Safe {
    token hex_after    { <?{}> }   # disable trailing hex check
}

my grammar Unsafe is IPv4::Grammar::Safe {
    token leading_zero { <?{}> }   # disable leading zero checks
}

my grammar Padded is IPv4::Grammar::Safe {
    token octet_pad    { \s* }     # disable space padding checks
}

my grammar Insane is IPv4::Grammar::Safe {
    token hex_after    { <?{}> }   # disable trailing hex check
    token octet_pad    { \s*[ 0 <.before <.digit>**3 > ]? } # allow pad and an extra leading zero
    token leading_zero { <?{}> }   # disable leading zero checks
}

sub saneparse ($s, $r) {
    my $m;
    $m = IPv4::Grammar::Safe.parse($s, :rule($r));
    $m ~~ Failure and return $m.exception.Str;
    return $m.ast.perl;
}

sub lasthexparse ($s, $r) {
    my $m;
    $m = Lasthex.parse($s, :rule($r));
    $m ~~ Failure and return $m.exception.Str;
    return $m.ast.perl;
}

sub paddedparse ($s, $r) {
    my $m;
    $m = Padded.parse($s, :rule($r));
    $m ~~ Failure and return $m.exception.Str;
    return $m.ast.perl;
}

sub unsafeparse ($s, $r) {
    my $m;
    $m = Unsafe.parse($s, :rule($r));
    $m ~~ Failure and return $m.exception.Str;
    return $m.ast.perl;
}

sub insaneparse ($s, $r) {
    my $m;
    $m = Insane.parse($s, :rule($r));
    $m ~~ Failure and return $m.exception.Str;
    return $m.ast.perl;
}

my $errmsg;

is saneparse("0.0.0.0","dotted"),
   "(0, 0, 0, 0)", "parse zeros as dotted";
is saneparse("0.0.0.0","subnet_mask"),
   "(0, 0, 0, 0)", "parse zeros as subnet_mask";
is saneparse("0.0.0.0","acenet_mask"),
   "(0, 0, 0, 0)", "parse zeros as acenet_mask";
is saneparse("255.255.255.255","subnet_mask"),
   "(255, 255, 255, 255)", "parse ones as subnet_mask";
is saneparse("255.255.255.255","acenet_mask"),
   "(255, 255, 255, 255)", "parse ones as acenet_mask";
is saneparse("192.0.2.0/25","cidr"),
   "((192, 0, 2, 0), 25)", "parse CIDR netblock";
is saneparse("192.0.2.0 255.255.255.240","subnet"),
   "((192, 0, 2, 0), (255, 255, 255, 240))", "parse subnet";
is saneparse("192.0.2.0 0.0.0.15","acenet"),
   "((192, 0, 2, 0), (0, 0, 0, 15))", "parse ACE net";
is saneparse("192.0.2.10/24","cidrsta"),
   "((192, 0, 2, 10), 24)", "parse CIDR-style ifaddr";
is saneparse("192.0.2.1 255.255.255.248","substa"),
   "((192, 0, 2, 1), (255, 255, 255, 248))", "parse subnet style ifaddr";
is saneparse("192.0.2.1 0.0.0.7","acesta"),
   "((192, 0, 2, 1), (0, 0, 0, 7))", "parse ACE style ifaddr";
is saneparse("192.0.2.1 0.255.0.255","filter"),
   "((192, 0, 2, 1), (0, 255, 0, 255))", "parse freeform filter";

is saneparse("0.0.0.255","acenet_mask"),
   "(0, 0, 0, 255)", "parse valid acenet_mask class C";
is saneparse("0.0.255.255","acenet_mask"),
   "(0, 0, 255, 255)", "parse valid acenet_mask class B";
is saneparse("0.255.255.255","acenet_mask"),
   "(0, 255, 255, 255)", "parse valid acenet_mask class A";

is saneparse("0.0.0.127","acenet_mask"),
   "(0, 0, 0, 127)", "parse valid acenet_mask octet 0 bit 7";
is saneparse("0.0.63.255","acenet_mask"),
   "(0, 0, 63, 255)", "parse valid acenet_mask octet 1 bit 6";
is saneparse("0.31.255.255","acenet_mask"),
   "(0, 31, 255, 255)", "parse valid acenet_mask octet 2 bit 5";
is saneparse("15.255.255.255","acenet_mask"),
   "(15, 255, 255, 255)", "parse valid acenet_mask octet 3 bit 4";

is saneparse("0.0.0.7","acenet_mask"),
   "(0, 0, 0, 7)", "parse valid acenet_mask octet 0 bit 3";
is saneparse("0.0.3.255","acenet_mask"),
   "(0, 0, 3, 255)", "parse valid acenet_mask octet 1 bit 2";
is saneparse("0.1.255.255","acenet_mask"),
   "(0, 1, 255, 255)", "parse valid acenet_mask octet 2 bit 1";

is saneparse("0.0.0.254","acenet_mask"), 'Any',
    "silently reject invalid acenet_mask octet 3";
is saneparse("0.0.254.255","acenet_mask"), 'Any',
    "silently reject invalid acenet_mask octet 2";
is saneparse("0.254.255.255","acenet_mask"), 'Any',
    "silently reject invalid acenet_mask octet 1";
is saneparse("254.255.255.255","acenet_mask"), 'Any',
    "silently reject invalid acenet_mask octet 0";

is saneparse("255.255.255.0","acenet_mask"), 'Any',
    "silently reject subnet_mask class C as acenet_mask";
is saneparse("255.255.0.0","acenet_mask"), 'Any',
    "silently reject subnet_mask class B as acenet_mask";
is saneparse("255.0.0.0","acenet_mask"), 'Any',
    "silently reject subnet_mask class A as acenet_mask";

is saneparse("15.0.0.0","acenet_mask"), 'Any',
    "silently reject invalid acenet_mask composed of valid acenet_octets 0";
is saneparse("0.15.0.0","acenet_mask"), 'Any',
    "silently reject invalid acenet_mask composed of valid acenet_octets 1";
is saneparse("0.0.15.0","acenet_mask"), 'Any',
    "silently reject invalid acenet_mask composed of valid acenet_octets 2";

$errmsg = "Octet out of range";
is saneparse("0.0.256.0","dotted"), $errmsg,
   "reject out of range octet with helpful message (dotted)";
is saneparse("255.256.0.0","subnet_mask"), $errmsg,
   "reject out of range octet with helpful message (subnet_mask)";
is saneparse("0.0.256.255", "acenet_mask"), $errmsg,
   "reject out of range octet with helpful message (acenet_mask)";
is saneparse("10.0.0.0/33", "cidr"), 'Prefix length out of range',
   "reject out of range CIDR prefix length with helpful message";

$errmsg = 'Whitespace in octet. Maybe use lenient grammar?';
is saneparse("100.100. 99.100","dotted"), $errmsg,
   "reject space padding with helpful message (octet)";
is saneparse("255.255. 128.0","subnet_mask"), $errmsg,
   "reject space padding with helpful message (sub_octet)";
is saneparse("0.0. 15.255","acenet_mask"), $errmsg,
   "reject space padding with helpful message (ace_octet)";
is saneparse("0. 0.15.255","acenet_mask"), $errmsg,
   "reject space padding with helpful message (octet0)";
is saneparse("0.15. 255.255","acenet_mask"), $errmsg,
   "reject space padding with helpful message (octet255)";

$errmsg = 'Possible hex in last octet.  Maybe use lenient grammar?';
is saneparse("0.0.0.0x","dotted"), $errmsg,
   "reject hex after last octet with helpful message (octet 0x)";
is saneparse("0.0.0.0A","dotted"), $errmsg,
   "reject hex after last octet with helpful message (octet 0A)";
is saneparse("0.0.0.5a","dotted"), $errmsg,
   "reject hex after last octet with helpful message (octet 5a)";
is saneparse("255.255.255.0x","subnet_mask"), $errmsg,
   "reject hex after last octet with helpful message (sub_octet)";
is saneparse("0.0.0.0x","acenet_mask"), $errmsg,
   "reject hex after last octet with helpful message (ace_octet)";
is saneparse("255.0.0.0x","subnet_mask"), $errmsg,
   "reject hex after last octet with helpful message (octet0)";

$errmsg = 'Possible hex in octet.  Maybe use aton grammar?';
is saneparse("10.2A.30.40","dotted"), $errmsg,
   "reject hex in octet with helpful message (octet)";
is saneparse("255.255.1A.0","subnet_mask"), $errmsg,
   "reject hex in octet with helpful message (sub_octet)";
is saneparse("0.1A.255.255","acenet_mask"), $errmsg,
   "reject hex in octet with helpful message (ace_octet)";
is saneparse("255.0.0xA.0","subnet_mask"), $errmsg,
   "reject hex in octet with helpful message (octet0)";

$errmsg = 'Leading zero ambiguous.  Use aton(octal) or lenient(decimal) grammar.';
is saneparse("10.02.30.40","dotted"), $errmsg,
   "reject leading zero with helpful message (octet)";
is saneparse("255.255.255.000","subnet_mask"), $errmsg,
   "reject leading zero with helpful message (sub_octet)";
is saneparse("0.0.0.015","acenet_mask"), $errmsg,
   "reject leading zero with helpful message (ace_octet)";
is saneparse("255.0.000.0","subnet_mask"), $errmsg,
   "reject leading zero with helpful message (octet0)";
is saneparse("00.0.0.0","acenet_mask"), $errmsg,
   "reject leading zero with helpful message (octet255)";
is saneparse("10.0.0.0/08","cidr"), $errmsg,
   "reject leading zero with helpful message (prefix_length)";

is lasthexparse("10.8.134.4a","dotted"),
   "(10, 8, 134, 4)", "lenience on trailing hex-like works (octet)";
is lasthexparse("255.255.0.0a","subnet_mask"),
   "(255, 255, 0, 0)", "lenience on trailing hex-like works (octet0)";
is lasthexparse("0.0.0.7a","acenet_mask"),
   "(0, 0, 0, 7)", "lenience on trailing hex-like works (ace_octet)";

is paddedparse(" 10.  8.134. 47","dotted"),
   "(10, 8, 134, 47)", "lenience on padding works (dotted)";
is paddedparse("255. 128.  0.  0","subnet_mask"),
   "(255, 128, 0, 0)", "lenience on padding works (subnet_mask)";
is paddedparse("  0.  0. 15.255","acenet_mask"),
   "(0, 0, 15, 255)", "lenience on padding works (acenet_mask)";

is unsafeparse("010.008.134.047","dotted"),
   "(10, 8, 134, 47)", "lenience on leading zero works (dotted)";
is unsafeparse("255.128.000.000","subnet_mask"),
   "(255, 128, 0, 0)", "lenience on leading zero works (subnet_mask)";
is unsafeparse("0.000.15.255.255","acenet_mask"),
   "(0, 0, 15, 255)", "lenience on leading zero works (acenet_mask)";
is unsafeparse("010.0.00.000/08","cidr"),
   "((10, 0, 0, 0), 8)", "lenience on leading zero works (cidr)";

is insaneparse("0010. 0008.134.   00b","dotted"),
   "(10, 8, 134, 0)", "lenience combo works (octet)";
is insaneparse(" 0010. 0008.134.   0x","dotted"),
   "(10, 8, 134, 0)", "lenience combo works #2 (octet)";
is insaneparse("0255.  0.  000.    0b","subnet_mask"),
   "(255, 0, 0, 0)", "lenience combo works (octet0)";
is insaneparse("   0. 0000.  015. 0255","acenet_mask"),
   "(0, 0, 15, 255)", "lenience combo works #2 (octet255)";
