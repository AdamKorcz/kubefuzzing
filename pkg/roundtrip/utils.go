// Copyright 2023 the kubefuzzing authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package roundtrip

import (
	"strings"
	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func randomLabelKey(c fuzz.Continue) (string, error) {
	namePart, err := randomLabelPart(c, false)
	if err != nil {
		return "", err
	}
	prefixPart := ""

	usePrefix, err := c.F.GetBool()
	if err != nil {
		return "", err
	}
	if usePrefix {
		// we can fit, with dots, at most 3 labels in the 253 allotted characters
		prefixPartsLen, err := c.F.GetInt()
		if err != nil {
			return "", err
			//:= c.Rand.Intn(2) + 1
		}
		if prefixPartsLen == 0 {
			return "", err
		}
		prefixParts := make([]string, prefixPartsLen%3)
		for i := range prefixParts {
			l, err := randomDNSLabel(c)
			if err != nil {
				return "", err
			}
			prefixParts[i] = l
		}
		prefixPart = strings.Join(prefixParts, ".") + "/"
	}

	return prefixPart + namePart, nil
}

// taken from gofuzz internals for RandString
type charRange struct {
	first, last rune
}

func (c *charRange) choose(inc int64) rune {

	count := int64(c.last - c.first + 1)
	ch := c.first + rune(inc%count)

	return ch
}

// randomLabelPart produces a valid random label value or name-part
// of a label key.
func randomLabelPart(c fuzz.Continue, canBeEmpty bool) (string, error) {
	startRune, err := c.F.GetInt()
	if err != nil {
		return "", err
	}

	inc, err := c.F.GetInt()
	if err != nil {
		return "", err
	}

	validStartEnd := []charRange{{'0', '9'}, {'a', 'z'}, {'A', 'Z'}}
	validMiddle := []charRange{{'0', '9'}, {'a', 'z'}, {'A', 'Z'},
		{'.', '.'}, {'-', '-'}, {'_', '_'}}

	partLen, err := c.F.GetInt() // len is [0, 63]
	if err != nil {
		return "", err
	}
	partLen = partLen % 64
	if !canBeEmpty {
		if partLen == 0 {
			partLen++
		}
	}

	runes := make([]rune, partLen)
	if partLen == 0 {
		return string(runes), nil
	}

	runes[0] = validStartEnd[startRune%len(validStartEnd)].choose(int64(inc))
	for i := range runes[1:] {

		inc, err := c.F.GetInt()
		if err != nil {
			return "", err
		}

		ind, err := c.F.GetInt()
		if err != nil {
			return "", err
		}

		runes[i+1] = validMiddle[ind%len(validMiddle)].choose(int64(inc))
	}
	ind, err := c.F.GetInt()
	if err != nil {
		return "", err
	}
	inc, err = c.F.GetInt()
	if err != nil {
		return "", err
	}

	runes[len(runes)-1] = validStartEnd[ind%len(validStartEnd)].choose(int64(inc))

	return string(runes), nil
}

func randomDNSLabel(c fuzz.Continue) (string, error) {
	startRune, err := c.F.GetInt()
	if err != nil {
		return "", err
	}

	inc, err := c.F.GetInt()
	if err != nil {
		return "", err
	}

	partLen, err := c.F.GetInt()
	if err != nil {
		return "", err
	}
	partLen = partLen % 63
	if partLen == 0 {
		partLen = 2
	}
	validStartEnd := []charRange{{'0', '9'}, {'a', 'z'}}
	validMiddle := []charRange{{'0', '9'}, {'a', 'z'}, {'-', '-'}}

	//partLen := c.Rand.Intn(63) + 1 // len is [1, 63]
	runes := make([]rune, partLen)

	runes[0] = validStartEnd[startRune%len(validStartEnd)].choose(int64(inc))
	for i := range runes[1:] {
		ind, err := c.F.GetInt()
		if err != nil {
			return "", err
		}
		inc, err = c.F.GetInt()
		if err != nil {
			return "", err
		}

		runes[i+1] = validMiddle[ind%len(validMiddle)].choose(int64(inc))
	}
	ind, err := c.F.GetInt()
	if err != nil {
		return "", err
	}
	inc, err = c.F.GetInt()
	if err != nil {
		return "", err
	}
	runes[len(runes)-1] = validStartEnd[ind%len(validStartEnd)].choose(int64(inc))

	return string(runes), nil
}