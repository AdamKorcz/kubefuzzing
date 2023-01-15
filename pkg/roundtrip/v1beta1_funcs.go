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

	fuzz "github.com/AdaLogics/go-fuzz-headers"

	metav1beta1 "k8s.io/apimachinery/pkg/apis/meta/v1beta1"
)

func V1beta1FuzzerFuncs() []interface{} {
	return []interface{}{
		func(r *metav1beta1.TableOptions, c fuzz.Continue) error {
			c.GenerateStruct(r)
			// NoHeaders is not serialized to the wire but is allowed within the versioned
			// type because we don't use meta internal types in the client and API server.
			r.NoHeaders = false
			return nil
		},
		func(r *metav1beta1.TableRow, c fuzz.Continue) error {
			c.GenerateStruct(&r.Object)
			c.GenerateStruct(&r.Conditions)
			if len(r.Conditions) == 0 {
				r.Conditions = nil
			}
			n, err := c.F.GetInt()
			if err != nil {
				return err
			}
			if n > 0 {
				r.Cells = make([]interface{}, n%10)
			}
			for i := range r.Cells {
				t, err := c.F.GetInt()
				if err != nil {
					return err
				}
				switch t % 5 {
				case 0:
					randString, err := c.F.GetString()
					if err != nil {
						return err
					}
					r.Cells[i] = randString
				case 1:
					randInt64, err := c.F.GetInt()
					if err != nil {
						return err
					}
					r.Cells[i] = int64(randInt64)
				case 2:
					b, err := c.F.GetBool()
					if err != nil {
						return err
					}
					r.Cells[i] = b
				case 3:
					x := map[string]interface{}{}
					n, err := c.F.GetInt()
					if err != nil {
						return err
					}

					for j := n%10 + 1; j >= 0; j-- {
						key, err := c.F.GetString()
						if err != nil {
							return err
						}
						value, err := c.F.GetString()
						if err != nil {
							return err
						}
						x[key] = value
					}
					r.Cells[i] = x
				case 4:
					n, err := c.F.GetInt()
					if err != nil {
						return err
					}
					x := make([]interface{}, n%10)
					for i := range x {
						randInt, err := c.F.GetInt()
						if err != nil {
							return err
						}
						x[i] = int64(randInt)
					}
					r.Cells[i] = x
				default:
					r.Cells[i] = nil
				}
			}
			return nil
		},
	}
}
