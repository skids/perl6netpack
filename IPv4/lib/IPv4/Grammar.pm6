
module IPv4::Grammar;

=begin pod

=head1 NAME

IPv4::Grammar - Perl6 grammars for IPv4-related textual representations

=head1 SYNOPSIS

  use IPv4::Grammar;

  # Parse octets from an address
  my Int @ip = IPv4::Grammar::Safe.parse("192.0.2.0",:rule<dotted>).ast;

  # Find valid netmasks in an array of addresses
  @valid = < 255.255.255.0 255.255.255.1 255.255.240.0 255.0.255.0 >.grep(
             { IPv4::Grammar::Safe.parse($_, :rule<subnet_mask>) });

  # Use this rule instead for inverted ACE-style wildcard masks
  say so IPv4::Grammar::Safe.parse("0.0.15.255",:rule<acenet_mask>); # True

  # Separate a CIDR address with prefix length into two sanitized strings
  $m = IPv4::Grammar::Safe.parse("203.0.113.0/24",:rule<cidr>); # True
  ($net, $pre) = $m<dotted prefix_length>.map({.Str});

  # But this would fail because the host portion extends past the mask:
  say so IPv4::Grammar::Safe.parse("203.0.113.1/24",:rule<cidr>); # False

  # So for e.g. iproute2 interface addresses, use this rule instead:
  $m = IPv4::Grammar::Safe.parse("203.0.113.1/24",:rule<cidrsta>);
  ($sta, $pre) = $m<dotted prefix_length>.map({.Str});

  # There are also rules for ACE fragments
  IPv4::Grammar::Safe.parse("203.0.113.1 0.0.0.255",:rule<acenet>); # False
  IPv4::Grammar::Safe.parse("203.0.113.1 0.0.0.255",:rule<acesta>); # True

  # And variants for routes and interface addresses
  IPv4::Grammar::Safe.parse("203.0.113.1 255.255.255.0",:rule<subnet>); # False
  IPv4::Grammar::Safe.parse("203.0.113.1 255.255.255.0",:rule<substa>); # True

  # If you need to customize further there are plenty of rules to override:
  my grammar ScrapeIPs is IPv4::Grammar::Safe {
    rule substa_separator { '/' };  # 203.0.113.1/255.255.255.0 instead
    rule octet_pad { \s**0..1 };    # allow some padding spaces in octets
  }
  ScrapeIPs.parse("192.  0.  2. 13/255.255.255.  0",:rule<substa>); # True

  # You may also customize actions
  my class CarpCIDR is IPv4::Grammar::Actions {
    method cidr($/) { "Found a CIDR".warn; nextsame; }
  }
  ScrapeIPs.parse("192.0.2.1/255.255.255.0",:actions(CarpCIDR),:rule<cidr>);

  # Return values may be pending Failure with helpful error message
  $c = IPv4::Grammar::Safe.parse("255.256.255.0/24",:rule<cidr>);
  $c.exception.Str.say if ($c ~~ Failure); # "Octet out of range"

=head1 DESCRIPTION

C<IPv4::Grammar> provides grammars to be used internally by the
Perl6 IPv4:: modules, and may also be useful for roll-your-own purposes.

Right about now you are probably thinking "all I want to do is parse an
IP address, why can't I just C<m/(\d**1..3)**4 % '.'/?>."  Well, the answer
is because people (and machines) manage to find the strangest ways to
break even the simplest things.  For example if you were to feed the
address C<198.51.100.011> into some computer programs, they would try
to connect to C<198.51.100.9>, while other programs would try to connect
to C<198.51.100.11>.

For a lark, or if you really want to understand some of the more obscure
IP address textual formats, or just marvel at the community's inability
to standardize see L<http://tools.ietf.org/html/draft-main-ipaddr-text-rep-02>.
(Bring a bucket of popcorn.  You'll need both.)

The C<IPv4::Grammar::Safe> grammar aims to provide a way to parse IP addresses
strictly, failing to match when any potentially unsafe condition occurs, and
generate helpful error messages to aid in debugging applications.  Only
IP addresses generated in the safest manner possible will parse cleanly.
This means situations where a faulty generator of textual IP addresses
is in use will be brought to the attention of the application developer.

For use cases where this grammar is too strict, and the source of the
parsed text cannot be fixed to generate IP representations safely, a lot
of customization hooks are provided to easily generate new, more lenient
grammars with some of the safety checks removed.

In the future, a separate grammar to process the more cretinous
inet_aton(3) address formats may also be provided in this package, but not
until someone actually needs one enough to ask for it.

=head1 ACTIONS

The C<class IPv4::Grammar::Actions> contains default actions that will
produce simple Int values in the abstract syntax tree.  Actions
are documented along with their corresponding tokens below.  There is no
need to explicitly specify C<:actions(IPv4::Grammar::Actions)> as an
argument to the C<parse> method of C<IPv4::Grammar::Safe>; using it is
the default.

=end pod

our class Actions {
    method octet ($/)            { make $0.Int }
    method octet_ ($/)           { make $/<octet>.ast }
    method prefix_length ($/)    { make $0.Int }
    method stray_prefix_length ($/)    { make $/<prefix_length>.ast }
    method dotted($/)            { make $/<octet>>>.ast; }
    method subnet_mask($/)       { make $/<octet>>>.ast; }
    method acenet_mask($/)       { make $/<octet>>>.ast; }
    method cidr ($/)             { make $/<dotted prefix_length>>>.ast }
    method subnet ($/)           { make $/<dotted subnet_mask>>>.ast }
    method acenet ($/)           { make $/<dotted acenet_mask>>>.ast }
    method filter ($/)           { make $/<dotted>>>.ast }
    method substa ($/)           { make $/<dotted subnet_mask>>>.ast }
    method acesta ($/)           { make $/<dotted acenet_mask>>>.ast }
    method cidrsta ($/)          { make $/<dotted prefix_length>>>.ast }
}

# This is probative and not formally offered as API yet.  Perl6 specs should
# probably define a "proper" place to put rules used to reconstruct
# normative representations.  But of course, reconstruct to what exactly
# and from what exactly?  A common pattern/need would be to emit a
# "cleaned up" reconstruction from a previous Match, but users may elect
# not to keep the Match around and just pull out the AST, so reconstructing
# from an AST would seem useful.  The form of the AST relies on the :actions
# class used, so if a user changed the :actions they would also have to
# be responsible for changing this.
#
# One way to gain this level of flexibility might be to leverage MMD.
# A base class would provide methods named after action methods with
# a signature of ( Match $m ).  A subclass could then add methods of
# different signatures to handle AST contents instead of Match objects.
# MMD would dispatch to the appropriate versions depending on what the
# (corrolary to .parse) was fed.  The only icky part with this strategy
# is it falls apart if there is a good reason for the AST to be
# containing Match objects from other sources.  A "Just don't do that"
# public policy might be OK though.
#
# Anyway, for now we are only concerned with using a proper set of
# separators, so we just define those; they do not care what they
# are being fed.
our class Emit {
    method dot (|c) { '.' }
    method cidr_separator (|c) { '/' }
    method subnet_separator (|c) { ' ' }
    method acenet_separator (|c) { ' ' }
    method cidrsta_separator (|c) { '/' }
    method substa_separator (|c) { ' ' }
    method acesta_separator (|c) { ' ' }
    method filter_separator (|c) { ' ' }
}

our grammar Safe {

    method parse($target, :$rule?, :$actions = Actions, *%opt) {
        nextwith($target, :rule($rule), :actions($actions), %opt);
    }

    method emit($target, :$rule = 'TOP', :$emit = Emit, *%opt) {
        # for now just call designated rule.
        $emit."$rule"($target);
    }

=begin pod

=head2 GRAMMAR LENIENCY

The following rules in C<IPv4::Grammar::Safe> can be overridden to allow
for more lenient parsing.  This comes at the cost of allowing potential
ambiguities.  See the SYNOPSIS above for an example of creating a more
lenient grammar.

These rules are lookahead assertions and have no associated actions.

    =head3 token leading_zero

    Replace the C<leading_zero> rule with an expression that always
    evaluates to false to allow leading zeros in octets.  The
    maximum number of digits in an octet will still be 3, and octets
    will still always have decimal semantics.  Note that if this is
    done, the grammar will not detect generators that might run afoul
    of inet_aton(3) octal representations.

=end pod

    token leading_zero {
	0\d
	{ fail "Leading zero ambiguous." ~
	       "  Use aton(octal) or lenient(decimal) grammar." }
    }

=begin pod

    =head3 token hex_after

    Replace the C<hex_after> rule with an expression that always
    returns false to allow poorly delimited IP addresses to
    be followed by a hexadecimal digit or x or X.  Hex digits appearing
    in octets before the last one will still generate error messages,
    in addition to failing to parse.

    Note that if this is done, the grammar will not detect generators
    that might run afoul of inet_aton(3) hexadecimal representation rules.
    (e.g. C<0.0.0.0X80> might mean C<0.0.0.128> to some programs, while
    others would parse C<0.0.0.0> and leave the C<X80> as extra cruft.)

=end pod

    token hexoctet {
	[ \d? \d? <[a..fA..F]> | 0x | 0X ]
	{ fail "Possible hex in octet.  Maybe use aton grammar?" }
    }

    token hex_after {
	[ \d? \d? <[a..fA..F]> | 0x | 0X ]
	{ fail "Possible hex in last octet.  Maybe use lenient grammar?" }
    }

=begin pod

    =head3 token octet_pad

    Replace the C<octet_pad> rule with one that eats whatever padding may
    occur to the left of octets, for example C<{ \s?\s? }> would allow
    up to two spaces before any octet.  This is not counted towards the
    three-digit limit on octet values, however, so the previous example
    would allow C<"  254">.  The padding may also occur before the first
    octet.

    Note that when padding is allowed, the grammar will parse a pretty
    wide set of possible input patterns, so this would make fishing IP
    addresses out from surrounding decimal data more error prone.

=end pod

    token octet_pad {
       <!before \s> ||
       { fail "Whitespace in octet. Maybe use lenient grammar?" }
    }

=begin pod
=head2 MORE TOKENS AND METHODS

    Other overridable tokens may be used to further alter the grammar
    and certain action methods may also be overridden to change the values
    which are placed in the C<.ast> Abstract Syntax Tree in corresponding
    Match objects.

    =head3 token octet

    Matches any of the strings "0".."255".  In a lenient grammar
    variant, may also matches "000".."099" and "00".."09" with
    decimal, not octal, semantics.

    Note that when used on its own, this token will not fail if
    it is followed by material that looks suspiciously hexadecimal.

    Upon a successful match, a default action for this token will
    coerce the match to an C<Int> and add it to the abstract syntax
    tree.  If you provide an alternative action, you will probably
    be needing to modify a bunch of other such methods which rely
    on this behavior; Those are all mentioned below.

=end pod

    token octet_oob {
        <before ( \d**1..3 ) <?{ $0.Int < 256 or fail "Octet out of range";}> >
    }

    token octet { <.octet_pad> <!.leading_zero> <.octet_oob> ( \d**1..3 ) }

    # This wraps octet on all but the last octet in a dotted quad.
    token octet_ { <.octet_pad> <!.hexoctet> <octet> }

    token octet0 { <.octet_pad> <!.leading_zero> <.octet_oob>
        <.before ( [ 0 <!digit> ] || [ 00 <!digit> ] || [ 000 ]) >
    }

    token octet0_ { <.octet_pad> <!.hexoctet> <.octet0> }

    token octet255 { <.octet_pad> <!.leading_zero> <.octet_oob> <.before 255> }

    token octet255_ { <.octet_pad> <!.hexoctet> <.octet255> }

=begin pod
    =head3 token sub_octet

    Matches any of the strings "255", "254", "252, "248", "240",
    "224", "192", "128", and "0".  In a lenient grammar variant,
    may also match "00" and "000".

    This token is always followed by an C<octet> token, and so
    does not have a corresponding action.

=end pod

    token sub_octet {
        <.octet_pad> <!.leading_zero> <.octet_oob>
        <.before ( 255 | 254 | 252 | 248 | 240 | 224 |
                   192 | 128 | 000 |  00 |   0 ) >
    };

    token sub_octet_ { <.octet_pad> <!.hexoctet> <.sub_octet> };

=begin pod
    =head3 token ace_octet

    Matches any of the strings "255", "127", "63, "31", "15",
    "7", "3", "1", and "0".  In a lenient grammar variant,
    may also match "063", "031", "015", "07", "007", "03", "003",
    "01", "001", "00" and "000", with decimal semantics.

    This token is always followed by an C<octet> token, and so
    does not have a corresponding action.

=end pod

    token ace_octet {
        <.octet_pad> <!.leading_zero> <.octet_oob>
        <.before ( 255 | 127 |  63 |  31 | 15 |   7 |  3 |   1 |  0 |  00 |
                   000 | 062 | 031 | 015 | 07 | 007 | 03 | 003 | 01 | 001 ) >
    };

    token ace_octet_ { <.octet_pad> <!.hexoctet> <.ace_octet> };

=begin pod
    =head3 token prefix_length

    Matches any of the strings C<"0".."32">.  In a lenient
    grammar variant, may also match C<"00".."09">.  This token
    is used internally by the C<cidr> and C<cidrsta> tokens.

    Upon a successful match, a default action for this token will
    coerce the match to an C<Int> and add it to the abstract syntax
    tree.  This can be overridden via the corresponding action method.

=end pod

    token prefix_length_oob {
        <before ( \d**1..2 )
	 <?{ $0.Int < 33 or fail "Prefix length out of range";}>
         >
    };

    token prefix_length {
        <!.hex_after> <!.leading_zero> <prefix_length_oob> ( \d**1..2 )
    };

=begin pod
    =head3 token stray_prefix_length

    As per the C<prefix_length> token, but allows a leading C<cidr_separator>
    token.

=end pod

    token stray_prefix_length {
        <.cidr_separator>? <prefix_length>
    };

=begin pod
    =head3 token dotted

    Parses an address in dotted quad notation.  The C<.> default
    separator may be overridden with the token C<dot>.  Overriding
    either C<dotted> or C<dot> will affect many of the below rules,
    which use these tokens internally.  Note that the dotted quads
    representing contiguous masks have their own tokens, so
    if you have reason to override C<dotted> you may need to override
    C<subnet_mask> and C<acenet_mask> similarly.

    If a lenient grammar is specified, leading zeros may be allowed
    in octets, with decimal, not octal, semantics, up to a maximum
    total length of three digits.

    Unless a lenient grammar variant is used, this token will
    fail if the supposed last octet is followed by any
    valid hexadecimal digit, or if it is zero and followed by
    "x" or "X", in order to detect possible radix errors.

    After a successful match, by default, the abstract syntax tree
    will contain a capture of C<(Int,Int,Int,Int)>.  This can be
    overridden via the corresponding action method.

=end pod

    token dot { '.' }

    token dotted { [ <octet=octet_> <.dot> ]**3 <!hex_after> <octet> }

=begin pod
    =head3 token subnet_mask

    Parses a leading-ones contiguous netmask in dotted quad notation.
    The mask must represent 0..32 contiguous 1 bits from the high
    order end followed by contiguous 0 bits for the rest of the
    value or the match will fail.

    For example, C<"255.255.255.128"> is a valid C<subnet_mask>, and
    C<"255.255.255.1"> is not.

    If a lenient grammar is specified, leading zeros may be allowed
    in octets, with decimal, not octal, semantics, up to a maximum
    total length of three digits.

    Unless a lenient grammar variant is used, this token will
    fail if the supposed last octet is followed by any
    valid hexadecimal digit, or if it is zero and followed by
    "x" or "X", in order to detect possible radix errors.

    After a successful match, by default, the abstract syntax tree
    will contain a capture of C<(Int,Int,Int,Int)>.  This can be
    overridden via the corresponding action method.

=end pod

    token subnet_mask {
        [
            [ <.octet255_> <octet=octet_> <.dot> ]**3
            <!.hex_after> <.sub_octet> <octet>
         ]
        ||
        [
            [ <.octet255_> <octet=octet_> <.dot> ]**2
            <.sub_octet_> <octet=octet_>
            <.dot> <!.hex_after> <octet0> <octet>
         ]
        ||
        [
            <.octet255_> <octet=octet_> <.dot>
            <.sub_octet_> <octet=octet_>
            <.dot> <.octet0_> <octet=octet_>
            <.dot> <!.hex_after> <.octet0> <octet>
         ]
        ||
        [
            <.sub_octet_> <octet=octet_>
            [ <.dot> <.octet0_> <octet=octet_> ]**2
            <.dot> <!.hex_after> <.octet0> <octet>
         ]
    }

=begin pod
    =head3 token acenet_mask

    Parses a trailing-ones contiguous netmask in dotted quad notation.
    The mask must represent 0..32 contiguous 0 bits from the high
    order end followed by contiguous 1 bits for the rest of the
    value or the match will fail.

    For example, C<"0.0.0.255"> is a valid C<acenet_mask>, and
    C<"0.0.0.254"> is not.

    If a lenient grammar is specified, leading zeros may be allowed
    in octets, with decimal, not octal, semantics, up to a maximum
    total length of three digits.

    Unless a lenient grammar variant is used, this token will
    fail if the supposed last octet is followed by any
    valid hexadecimal digit, or if it is zero and followed by
    "x" or "X", in order to detect possible radix errors.

    After a successful match, by default, the abstract syntax tree
    will contain a capture of C<(Int,Int,Int,Int)>.  This can be
    overridden via the corresponding action method.


=end pod

    token acenet_mask {
        [
            <.ace_octet> <octet=octet_>
            [ <.dot> <.octet255_> <octet=octet_> ]**2
            <.dot> <!.hex_after> <.octet255> <octet>
         ]
        ||
        [
            <.octet0_> <octet=octet_> <.dot>
            <.ace_octet> <octet=octet_>
            <.dot> <.octet255_> <octet=octet_>
            <.dot> <!.hex_after> <.octet255> <octet>
         ]
        ||
        [
            [ <.octet0_> <octet=octet_> <.dot> ]**2
            <.ace_octet> <octet=octet_>
            <.dot> <!.hex_after> <.octet255> <octet>
         ]
        ||
        [
            [ <.octet0_> <octet=octet_> <.dot> ]**3
            <!.hex_after> <.ace_octet> <octet>
         ]
    }

=begin pod
    =head3 token cidr

    Parses an address (in dotted quad notation) and a prefix length
    within C<"0".."32"> (or, additionally, decimal C<"00".."09"> if
    a lenient grammar is in use.)  The address portion must conform
    to the prefix length (all bits in the station portion being 0).

    For example, C<"203.0.113.0/24"> is a valid C<cidr>, and
    C<"203.0.113.1/24"> is not.

    If a lenient grammar is specified, leading zeros may be allowed
    in octets, with decimal, not octal, semantics, up to a maximum
    total length of three digits.

    Unless a lenient grammar variant is used, this token will
    fail if the supposed prefix length is followed by any
    valid hexadecimal digit, or if it is zero and followed by
    "x" or "X", in order to detect possible radix errors.

    This is the widely used CIDR notation.  The default separator is
    C<'/'>, which can be overridden via the token C<cidr_separator>.

    After a successful match, by default, the abstract syntax tree
    will contain a capture of C<((Int,Int,Int,Int),Int)>.
    This can be overridden via the corresponding action method.

=end pod

    token cidr_separator   { '/' };

    token cidr {
	<dotted> <.cidr_separator> <prefix_length>
	{ (0xffffffff +> $/<prefix_length>.ast) +&
	  [+|]($/<dotted>.ast <<+<>> (24,16,8,0))
	      and fail("Address does not conform to CIDR prefix length");
	 }
    };

=begin pod
    =head3 token subnet

    Parses an address and a contiguous network mask, both in dotted
    quad notation.  The mask must represent 0..32 contiguous 1 bits
    from the high order end followed by contiguous 0 bits for the rest
    of the value or the match will fail.  The address must be
    consistent with the mask (all bits 0 where the mask has a 0 bit) or
    the match will fail.

    For example, C<"203.0.113.0/255.255.255.0"> is a valid C<subnet>,
    and C<"203.0.113.1/255.255.255.0"> is not.

    If a lenient grammar is specified, leading zeros may be allowed
    in octets, with decimal, not octal, semantics, up to a maximum
    total length of three digits.

    This format is most commonly found in router static route definitions.
    The default separator is whitespace, which can be overridden via the
    token C<subnet_separator>.

    After a successful match, by default, the abstract syntax tree will
    contain a capture of C<((Int,Int,Int,Int),(Int,Int,Int,Int))>.
    This can be overridden via the corresponding action method.

=end pod

    token subnet_separator { <.ws> };

    token subnet {
	<dotted> <.subnet_separator> <subnet_mask>
	# XXX should not need the 255 here, prefix +^<< should work.
	{ none($/<dotted>.ast >>+&<< (255 <<+^<< $/<subnet_mask>.ast))
	      or fail("Address does not conform to subnet mask");
	 }
    };

=begin pod
    =head3 token acenet

    Parses an address and an inverted contiguous mask, both in dotted
    quad notation.  The mask must represent 0..32 contiguous 0 bits
    from the high order end followed by contiguous 1 bits for the
    rest of the value or the match will fail.  The address must be
    consistent with the mask (all bits 0 where the mask has a 1 bit) or
    The match will fail.

    For example, C<"203.0.113.0/0.0.0.255"> is a valid C<acenet>,
    and C<"203.0.113.1/0.0.0.255"> is not.

    If a lenient grammar is specified, leading zeros may be allowed
    in octets, with decimal, not octal, semantics, up to a maximum
    total length of three digits.

    This format is most commonly found in router access control list
    entries (ACEs).  The default separator is whitespace, which can be
    overridden via the token C<acenet_separator>.

    Unless a lenient grammar variant is used, this token will
    fail if the supposed last octet in either dotted quad is followed
    by any valid hexadecimal digit, or if it is "0" and followed by
    "x" or "X" (even if you have overridden the separator to start with
    "x" or "X"), in order to detect possible radix errors.

    After a successful match, by default, the abstract syntax tree will
    contain a capture of C<((Int,Int,Int,Int),(Int,Int,Int,Int))>.
    This can be overridden via the corresponding action method.

=end pod

    token acenet_separator { <.ws> };

    token acenet {
	<dotted> <.acenet_separator> <acenet_mask>
	{ none($/<dotted>.ast >>+&<< $/<acenet_mask>.ast)
	      or fail("Address does not conform to acenet mask");
	 }
    };

=begin pod
    =head3 token cidrsta

    Parses an address (in dotted quad notation) and a prefix length
    within C<"0".."32"> (or, additionally, C<"00".."09"> if the
    lenient grammar is in use.)  The address portion need not conform to
    the prefix length.

    If a lenient grammar is specified, leading zeros may be allowed
    in octets, with decimal, not octal, semantics, up to a maximum
    total length of three digits.

    Unless a lenient grammar variant is used, this token will
    fail if the supposed prefix length is followed by any
    valid hexadecimal digit, or if it is zero and followed by
    "x" or "X", in order to detect possible radix errors.

    This is the widely used CIDR notation, minus the requirement
    for the address to conform to the prefix length.  It is sometimes
    found when expressing an interface address tersely.  The default
    separator is C<'/'>, which can be overridden via the token
    C<cidrsta_separator>.

    Unless a lenient grammar variant is used, this token will
    fail if the supposed last octet in either dotted quad is followed
    by any valid hexadecimal digit, or if it is "0" and followed by
    "x" or "X" (even if you have overridden the separator to start with
    "x" or "X"), in order to detect possible radix errors.

    After a successful match, by default, the abstract syntax tree
    will contain a capture of C<((Int,Int,Int,Int),Int)>.  This can
    be overridden via the corresponding action method.

=end pod

    token cidrsta_separator { '/' }

    token cidrsta { <dotted> <.cidrsta_separator> <prefix_length> }


=begin pod
    =head3 token substa

    Parses an address and a contiguous network mask, both in dotted
    quad notation.  The mask must represent 0..32 contiguous 1 bits
    from the high order end followed by contiguous 0 bits for the
    rest of the value or the match will fail.  The address need not
    be constrained by the mask.

    If a lenient grammar is specified, leading zeros may be allowed
    in octets, with decimal, not octal, semantics, up to a maximum
    total length of three digits.

    This format is most commonly found in router interface configurations.
    The default separator is whitespace, which can be overridden via the
    token C<substa_separator>.

    Unless a lenient grammar variant is used, this token will
    fail if the supposed last octet in either dotted quad is followed
    by any valid hexadecimal digit, or if it is "0" and followed by
    "x" or "X" (even if you have overridden the separator to start with
    "x" or "X"), in order to detect possible radix errors.

    After a successful match, by default, the abstract syntax tree will
    contain a capture of C<((Int,Int,Int,Int),(Int,Int,Int,Int))>.
    This can be overridden via the corresponding action method.

=end pod

    token substa_separator { <.ws> }

    token substa { <dotted> <.substa_separator> <subnet_mask> }


=begin pod
    =head3 token acesta

    Parses an address and an inverted contiguous mask, both in dotted
    quad notation.  The mask must represent 0..32 contiguous 0 bits
    from the high order end followed by contiguous 1 bits for the
    rest of the value or the match will fail.  The address need
    not be constrained by the mask.

    If a lenient grammar is specified, leading zeros may be allowed
    in octets, with decimal, not octal, semantics, up to a maximum
    total length of three digits.

    This format is included for completeness and is rare in the wild.
    The default separator is whitespace, which can be overridden via the
    token C<acesta_separator>.

    Unless a lenient grammar variant is used, this token will
    fail if the supposed last octet in either dotted quad is followed
    by any valid hexadecimal digit, or if it is "0" and followed by
    "x" or "X" (even if you have overridden the separator to start with
    "x" or "X"), in order to detect possible radix errors.

    After a successful match, by default, the abstract syntax tree will
    contain a capture of C<((Int,Int,Int,Int),(Int,Int,Int,Int))>.
    This can be overridden via the corresponding action method.

=end pod

    token acesta_separator { <.ws> }

    token acesta { <dotted> <.acesta_separator> <acenet_mask> }


=begin pod
    =head3 token filter

    Parses an address and mask, both in dotted quad notation, with no
    restrictions on the contiguousness of the mask or the agreement of
    the mask and the address.

    If a lenient grammar is specified, leading zeros may be allowed
    in octets, with decimal, not octal, semantics, up to a maximum
    total length of three digits.

    The default separator is whitespace, which can be overridden via
    the token C<filter_separator>.

    Unless a lenient grammar variant is used, this token will
    fail if the supposed last octet in either dotted quad is followed
    by any valid hexadecimal digit, or if it is "0" and followed by
    "x" or "X" (even if you have overridden the separator to start with
    "x" or "X"), in order to detect possible radix errors.

    After a successful match, by default, the abstract syntax tree
    will contain a capture of C<((Int,Int,Int,Int),(Int,Int,Int,Int))>.
    This can be overridden via the corresponding action method.

=end pod

    token filter_separator { <.ws> }

    token filter { <dotted> <.filter_separator> <dotted> }

}

=begin pod
=head1 AUTHOR
       Brian S. Julin        bri@abrij.org

       Copyright © 2012 Brian S. Julin. All rights reserved.  This
       code is free software; you can redistribute it and/or modify it
       under the terms of the Perl Artistic License.

=head1 VERSION

       Version 0.1  (Feb 6 2012)

=head1 SEE ALSO
       perl6(1)
=end pod
