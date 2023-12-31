# Varsig

A rust implementation of the varsig ["spec"](https://github.com/ChainAgnostic/varsig).

This implementation fully supports the varsig spec linked above but it also
supports a propsed version 2 of the specification that gives more data to tools
even when they don't recognize the key codec. The two versions are detailed
below. The main difference is the location of the encoding codec.

Varsig version 2 uses a new codec sigil `0x39` instead of the original `0x34`
to distinguish the two formats.

## Varsig v1 Format 

```
                         payload encoding
     key codec                codec
         |                      |
         v                      v
0x34 <varuint> N(<varuint>) <varuint> N(OCTET)
^                    ^                    ^
|                    |                    |
varsig      variable number of     variable number
v1 sigil    signature specific    of signature data
                   values              octets
```

The v1 format unfortunately has a variable number of signature-specific values 
immediately following the key codec and before the encoding codec. This makes
it impossible for a tool to decode the encoding codec when it doesn't recognize
the key codec. It is forced to treat everything after the key codec as 
unparsable data.

## Varsig v2 Format 

```
                                variable number of
                    count of    signature specific   count of
     key codec    attributes        attributes       signature octets
         |                  \            |          /
         v                   v           v         v
0x39 <varuint> <varuint> <varuint> N(<varuint>) <varuint> N(OCTET)
^                  ^                              ^
|                  |                              |
varsig      payload encoding               variable number
v2 sigil         codec                   of signature octets
```

The v2 format allows tools that don't recognize the key codec to at least parse
the encoding codec for the signed data as well as hold all of the signature-
specific information together as the remainder that couldn't be parsed. This is 
cleaner than the v1 format.
