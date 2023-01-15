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
	"fmt"

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	apitesting "k8s.io/apimachinery/pkg/api/apitesting"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
)

var fuzzCodecFactory runtimeserializer.CodecFactory

func SetCodecFactory(c runtimeserializer.CodecFactory) {
	fuzzCodecFactory = c
}

func GenericFuzzerFuncs() []interface{} {
	return []interface{}{
		func(q *resource.Quantity, c fuzz.Continue) error {
			newInt, err := c.F.GetInt()
			if err != nil {
				return err
			}
			*q = *resource.NewQuantity(int64(newInt%1000), resource.DecimalExponent)
			return nil
		},
		func(j *int, c fuzz.Continue) error {
			newInt, err := c.F.GetInt()
			if err != nil {
				return err
			}
			*j = newInt
			return nil
		},
		func(j **int, c fuzz.Continue) error {
			makeNonNil, err := c.F.GetBool()
			if err != nil {
				return err
			}
			if makeNonNil {
				newInt, err := c.F.GetInt()
				if err != nil {
					return err
				}
				i := newInt
				*j = &i
			} else {
				*j = nil
			}
			return nil
		},
		func(j *runtime.TypeMeta, c fuzz.Continue) error {
			// We have to customize the randomization of TypeMetas because their
			// APIVersion and Kind must remain blank in memory.
			j.APIVersion = ""
			j.Kind = ""
			return nil
		},
		func(j *runtime.Object, c fuzz.Continue) error {
			if true { //c.RandBool() {
				*j = &runtime.Unknown{
					// We do not set TypeMeta here because it is not carried through a round trip
					Raw:         []byte(`{"apiVersion":"unknown.group/unknown","kind":"Something","someKey":"someValue"}`),
					ContentType: runtime.ContentTypeJSON,
				}
			} else {
				types := []runtime.Object{&metav1.Status{}, &metav1.APIGroup{}}
				typeIndex, err := c.F.GetInt()
				if err != nil {
					return err
				}
				t := types[typeIndex%len(types)]
				c.F.GenerateWithCustom(t)
				*j = t
			}
			return nil
		},
		func(r *runtime.RawExtension, c fuzz.Continue) error {
			// Pick an arbitrary type and fuzz it
			types := []runtime.Object{&metav1.Status{}, &metav1.APIGroup{}}
			typeIndex, err := c.F.GetInt()
			if err != nil {
				return err
			}
			obj := types[typeIndex%len(types)]
			c.F.GenerateWithCustom(obj)

			// Find a codec for converting the object to raw bytes.  This is necessary for the
			// api version and kind to be correctly set be serialization.
			var codec = apitesting.TestCodec(fuzzCodecFactory, metav1.SchemeGroupVersion)

			// Convert the object to raw bytes
			bytes, err := runtime.Encode(codec, obj)
			if err != nil {
				panic(fmt.Sprintf("Failed to encode object: %v", err))
			}

			// strip trailing newlines which do not survive roundtrips
			for len(bytes) >= 1 && bytes[len(bytes)-1] == 10 {
				bytes = bytes[:len(bytes)-1]
			}

			// Set the bytes field on the RawExtension
			r.Raw = bytes
			return nil
		},
	}
}
