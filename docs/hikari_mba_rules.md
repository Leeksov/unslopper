# Hikari Substitution ruleset (inverse = simplification targets)

Source: Hikari-LLVM llvm-15.0.2 SubstituteImpl.cpp. The obfuscator applies the
RIGHT-hand form; our mba_simplify must recognize it and fold back to the LEFT.

## Flattening (Flattening.cpp)
- state var `switchVar` = 32-bit int on stack; pointer `switchVarAddr`
- initial state = scramble32(0, key) — randomized, NOT sequential
- case values = scramble32(caseIndex, key) — random 32-bit "magic" constants
- dispatcher = loopEntry (high preds) -> switch -> case blocks -> loopEnd -> loopEntry
- conditional edges use SelectInst(cond, trueCase, falseCase) == CSEL at asm level
  => our CSEL conditional-transition handling is correct

## ADD  (fold RHS -> a+b)
- a-(-b)
- -(-a+(-b))
- (a+r)+b-r          [random r — needs affine fold]
- (a-r)+b+r          [random r]
- a-(~b-1)  == a-(~b+(-1))
- (a|b)+(a&b)
- (a^b)+(a&b)*2

## SUB  (fold RHS -> a-b)
- a+(-b)
- (a+r)-b-r          [random r]
- (a-r)-b+r          [random r]
- (a&~b)-(~a&b)
- 2*(a&~b)-(a^b)
- a+~b+1

## AND  (fold RHS -> a&b)
- (a^~b)&a
- (a|b)&~(a^b)
- (~a|b)+(a+1)
- ~(~a|~b)           [De Morgan]
- Nor(Nor(a,a),Nor(b,b))   ; Nor(x,y)=~(x|y)
- Nand(Nand(a,b),Nand(a,b)); Nand(x,y)=~(x&y)

## OR  (fold RHS -> a|b)
- (a&b)|(a^b)
- (a+(a^b))-(a&~b)
- (a+b+1)+~(a&b)
- ~(~a&~b)           [De Morgan]
- Nor(Nor(a,b),Nor(a,b))
- Nand(Nand(a,a),Nand(b,b))

## XOR  (fold RHS -> a^b)
- (~a&b)|(a&~b)
- (a+b)-2*(a&b)
- a-(2*(b&~(a^b))-b)
- (a^r)^(b^r)        [random r — cancels]
- Nor/Nand nestings

## Random-constant variants (addRand, subRand, xorRand, andRand, orRand)
The injected constant r always cancels. An affine/constant-fold pass over the
expression tree removes them without needing the specific rule.
