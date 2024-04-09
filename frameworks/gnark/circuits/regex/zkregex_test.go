package regex

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func TestPreimage(t *testing.T) {
	assert := test.NewAssert(t)

	var regexCircuit RegexCircuit

	// assert.ProverFailed(&regexCircuit, &RegexCircuit{
	// 	Hash:     42,
	// 	PreImage: 42,
	// })

	for i := range regexCircuit.Queries {
		regexCircuit.Queries[i] = i
	}
	privateString := make([]*big.Int, stringLength)
	inputString := "In a small town nestled between rolling hills and vast fields, there lived a wise old man known throughout the lands for his profound wisdom and keen insight. People from villages far and wide would journey to seek his counsel on matters both big and small. His home, a quaint cottage adorned with flowering vines and surrounded by an enchanting garden, was a place of serenity and reflection. As the seasons changed, so did the questions of those who visited him. Yet, no matter the query, the wise man always had the right words to offer. It wasn't until a rainy evening, when a curious traveler inquired about the essence of happiness, that the wise man shared a secret long held close: true contentment is found not in seeking more, but in appreciating the present moment. The traveler pondered this as they noticed a sereneti painting on the wall, its colors vibrant even as dusk fell. The wise man's lesson was clear and resonant, echoing the traveler's own beliefs and experiences."
	for i, char := range inputString {
		if i < stringLength {
			privateString[i] = big.NewInt(int64(char))
			regexCircuit.PrivateString[i] = privateString[i]
		}
	}

	assert.SolvingSucceeded(&RegexCircuit{}, &regexCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

	assert.ProverSucceeded(&RegexCircuit{}, &regexCircuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

}
