package nfa_regex

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func TestPreimage(t *testing.T) {
	assert := test.NewAssert(t)

	var nfaRegexCircuit NfaRegexCircuit

	a := make([]*big.Int, stringLength)
	inputString := "(e|r)en.t"
	for i, char := range inputString {
		if i < stringLength {
			a[i] = big.NewInt(int64(char))
		}
	}

	b := make([]*big.Int, substringLength)
	regexPattern := "In a small town nestled between rolling hills and vast fields, there lived a wise old man known throughout the lands for his profound wisdom and keen insight. People from villages far and wide would journey to seek his counsel on matters both big and small. His home, a quaint cottage adorned with flowering vines and surrounded by an enchanting garden, was a place of serenity and reflection. As the seasons changed, so did the questions of those who visited him. Yet, no matter the query, the wise man always had the right words to offer. It wasnt until a rainy evening, when a curious traveler inquired about the essence of happiness, that the wise man shared a secret long held close: true contentment is found not in seeking more, but in appreciating the present moment. The traveler pondered this as they noticed a sereneti painting on the wall, its colors vibrant even as dusk fell. The wise mans lesson was clear and resonant, echoing the travelers own beliefs and experiences."
	for i, char := range regexPattern {
		if i < substringLength {
			b[i] = big.NewInt(int64(char))
		}
	}

	nfaRegexCircuit.X = 2
	nfaRegexCircuit.Y = 4

	for i := 0; i < stringLength; i++ {
		nfaRegexCircuit.A[i] = a[i]
	}

	for i := 0; i < substringLength; i++ {
		nfaRegexCircuit.B[i] = b[i]
	}

	assert.SolvingSucceeded(&NfaRegexCircuit{}, &nfaRegexCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.PLONK))

	assert.ProverSucceeded(&NfaRegexCircuit{}, &nfaRegexCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.PLONK))

}
