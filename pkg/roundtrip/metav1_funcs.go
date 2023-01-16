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
	"sort"
	"strconv"
	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func V1FuzzerFuncs() []interface{} {
	return []interface{}{
		func(j *metav1.Time, c fuzz.Continue) error {
			timeInt, err := c.F.GetUint64()
			if err != nil {
				return err
			}

			j.Time = time.Unix(int64(timeInt%(1000*365*24*60*60)), 0)
			return nil
		},
		func(j *metav1.TypeMeta, c fuzz.Continue) error {
			// We have to customize the randomization of TypeMetas because their
			// APIVersion and Kind must remain blank in memory.
			j.APIVersion = ""
			j.Kind = ""
			return nil
		},
		func(j *metav1.ObjectMeta, c fuzz.Continue) error {
			c.GenerateStruct(j)

			ri, err := c.F.GetInt()
			if err != nil {
				return err
			}
			j.ResourceVersion = strconv.FormatUint(uint64(ri), 10)
			chars := "abcdefghijklmnopqrstuvwxyz-1234567890"
			randString, err := c.F.GetStringFrom(chars, 63)
			if err != nil {
				return err
			}
			j.UID = types.UID(randString)

			randString2, err := c.F.GetStringFrom(chars, 20)
			if err != nil {
				return err
			}
			j.Name = randString2

			// Fuzzing sec and nsec in a smaller range (uint32 instead of int64),
			// so that the result Unix time is a valid date and can be parsed into RFC3339 format.
			var sec, nsec uint32
			c.GenerateStruct(&sec)
			c.GenerateStruct(&nsec)
			j.CreationTimestamp = metav1.Unix(int64(sec), int64(nsec)).Rfc3339Copy()

			if j.DeletionTimestamp != nil {
				c.GenerateStruct(&sec)
				c.GenerateStruct(&nsec)
				t := metav1.Unix(int64(sec), int64(nsec)).Rfc3339Copy()
				j.DeletionTimestamp = &t
			}

			if len(j.Labels) == 0 {
				j.Labels = nil
			} else {
				delete(j.Labels, "")
			}
			if len(j.Annotations) == 0 {
				j.Annotations = nil
			} else {
				delete(j.Annotations, "")
			}
			if len(j.OwnerReferences) == 0 {
				j.OwnerReferences = nil
			}
			if len(j.Finalizers) == 0 {
				j.Finalizers = nil
			}
			return nil
		},
		func(j *metav1.ResourceVersionMatch, c fuzz.Continue) error {
			matches := []metav1.ResourceVersionMatch{"", metav1.ResourceVersionMatchExact, metav1.ResourceVersionMatchNotOlderThan}
			ind, err := c.F.GetInt()
			if err != nil {
				return err
			}
			*j = matches[ind%len(matches)]
			return nil
		},
		func(j *metav1.ListMeta, c fuzz.Continue) error {
			ind, err := c.F.GetUint64()
			if err != nil {
				return err
			}
			j.ResourceVersion = strconv.FormatUint(ind, 10)
			randString, err := c.F.GetString()
			if err != nil {
				return err
			}
			j.SelfLink = randString
			return nil
		},
		func(j *metav1.LabelSelector, c fuzz.Continue) error {
			c.GenerateStruct(j)
			// we can't have an entirely empty selector, so force
			// use of MatchExpression if necessary
			if len(j.MatchLabels) == 0 && len(j.MatchExpressions) == 0 {
				length, err := c.F.GetInt()
				if err != nil {
					return err
				}
				j.MatchExpressions = make([]metav1.LabelSelectorRequirement, length%3)
			}

			if j.MatchLabels != nil {
				fuzzedMatchLabels := make(map[string]string, len(j.MatchLabels))
				for i := 0; i < len(j.MatchLabels); i++ {
					randLabel, err := randomLabelPart(c, true)
					if err != nil {
						return err
					}
					labelKey, err := randomLabelKey(c)
					if err != nil {
						return err
					}
					fuzzedMatchLabels[labelKey] = randLabel
				}
				j.MatchLabels = fuzzedMatchLabels
			}

			validOperators := []metav1.LabelSelectorOperator{
				metav1.LabelSelectorOpIn,
				metav1.LabelSelectorOpNotIn,
				metav1.LabelSelectorOpExists,
				metav1.LabelSelectorOpDoesNotExist,
			}

			if j.MatchExpressions != nil {
				// NB: the label selector parser code sorts match expressions by key, and sorts the values,
				// so we need to make sure ours are sorted as well here to preserve round-trip comparison.
				// In practice, not sorting doesn't hurt anything...

				for i := range j.MatchExpressions {
					req := metav1.LabelSelectorRequirement{}
					c.GenerateStruct(&req)
					labelKey, err := randomLabelKey(c)
					if err != nil {
						return err
					}
					req.Key = labelKey
					ind, err := c.F.GetInt()
					if err != nil {
						return err
					}
					req.Operator = validOperators[ind%len(validOperators)]
					if req.Operator == metav1.LabelSelectorOpIn || req.Operator == metav1.LabelSelectorOpNotIn {
						if len(req.Values) == 0 {
							length, err := c.F.GetInt()
							if err != nil {
								return err
							}
							// we must have some values here, so randomly choose a short length
							req.Values = make([]string, length%3)
						}
						for i := range req.Values {
							l, err := randomLabelPart(c, true)
							if err != nil {
								return err
							}
							req.Values[i] = l
						}
						sort.Strings(req.Values)
					} else {
						req.Values = nil
					}
					j.MatchExpressions[i] = req
				}

				sort.Slice(j.MatchExpressions, func(a, b int) bool { return j.MatchExpressions[a].Key < j.MatchExpressions[b].Key })

			}
			return nil
		},
		func(j *metav1.ManagedFieldsEntry, c fuzz.Continue) error {
			c.GenerateStruct(j)
			j.FieldsV1 = nil
			return nil
		},
	}
}
