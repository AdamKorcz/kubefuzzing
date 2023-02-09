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
	//"fmt"
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

			j.ResourceVersion = "123456789"
			ri, err := c.F.GetInt()
			if err == nil {
				j.ResourceVersion = strconv.FormatUint(uint64(ri), 10)
			}

			j.UID = types.UID("fuzz")
			chars := "abcdefghijklmnopqrstuvwxyz-1234567890"
			randString, err := c.F.GetStringFrom(chars, 63)
			if err == nil {
				j.UID = types.UID(randString)
			}

			j.Name = ""
			randString2, err := c.F.GetStringFrom(chars, 20)
			if err == nil {
				j.Name = randString2
			}

			// Namespace
			j.Namespace = "default"
			namespaceLength, err := c.F.GetInt()
			if err == nil {
				namespace, err := c.F.GetStringFrom(chars, namespaceLength%63)
				if err == nil {
					j.Namespace = namespace
				}
			}

			// GenerateName
			j.GenerateName = ""
			generateNameLength, err := c.F.GetInt()
			if err == nil {
				generateName, err := c.F.GetStringFrom(chars, generateNameLength%63)
				if err == nil {
					j.GenerateName = generateName
				}
			}

			// Fuzzing sec and nsec in a smaller range (uint32 instead of int64),
			// so that the result Unix time is a valid date and can be parsed into RFC3339 format.
			j.CreationTimestamp = metav1.Unix(int64(123), int64(123)).Rfc3339Copy()
			var sec, nsec uint32
			err = c.GenerateStruct(&sec)
			if err == nil {
				err = c.GenerateStruct(&nsec)
				if err == nil {
					j.CreationTimestamp = metav1.Unix(int64(sec), int64(nsec)).Rfc3339Copy()
				}
			}

			if j.DeletionTimestamp != nil {
				t := metav1.Unix(int64(123), int64(123)).Rfc3339Copy()
				j.DeletionTimestamp = &t

				err = c.GenerateStruct(&sec)
				if err == nil {
					err = c.GenerateStruct(&nsec)
					if err == nil {
						t := metav1.Unix(int64(sec), int64(nsec)).Rfc3339Copy()
						j.DeletionTimestamp = &t
					}
				}
			}

			fuzzMap := make(map[string]string)
			fuzzMap["fuzz"] = "fuzz"

			if len(j.Labels) == 0 {
				j.Labels = fuzzMap
			} else {
				delete(j.Labels, "")
				if len(j.Labels) == 0 {
					j.Labels = fuzzMap
				}
			}
			if len(j.Annotations) == 0 {
				j.Annotations = fuzzMap
			} else {
				delete(j.Annotations, "")
				if len(j.Annotations) == 0 {
					j.Annotations = fuzzMap
				}
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
			var ind int
			ind, err := c.F.GetInt()
			if err != nil {
				ind = 0
			}
			*j = matches[ind%len(matches)]
			return nil
		},
		func(j *metav1.ListMeta, c fuzz.Continue) error {
			var ind uint64
			var randString string
			ind, err := c.F.GetUint64()
			if err != nil {
				ind = 0
			}
			j.ResourceVersion = strconv.FormatUint(ind, 10)
			randString, err = c.F.GetString()
			if err != nil {
				randString = "fuzz"
			}
			j.SelfLink = randString
			return nil
		},
		func(j *metav1.LabelSelector, c fuzz.Continue) error {
			c.GenerateStruct(j)
			var length, ind int
			var randLabel, labelKey, l string
			var err error
			// we can't have an entirely empty selector, so force
			// use of MatchExpression if necessary
			if len(j.MatchLabels) == 0 && len(j.MatchExpressions) == 0 {
				length, err = c.F.GetInt()
				if err != nil {
					length = 1
				}
				j.MatchExpressions = make([]metav1.LabelSelectorRequirement, length%3)
			}

			if j.MatchLabels != nil {
				fuzzedMatchLabels := make(map[string]string, len(j.MatchLabels))
				for i := 0; i < len(j.MatchLabels); i++ {
					randLabel, err = randomLabelPart(c, true)
					if err != nil {
						randLabel = "fuzz"
					}
					labelKey, err = randomLabelKey(c)
					if err != nil {
						labelKey = "fuzz"
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
						labelKey = "fuzz"
					}
					req.Key = labelKey
					ind, err = c.F.GetInt()
					if err != nil {
						ind = 0
					}
					req.Operator = validOperators[ind%len(validOperators)]
					if req.Operator == metav1.LabelSelectorOpIn || req.Operator == metav1.LabelSelectorOpNotIn {
						if len(req.Values) == 0 {
							length, err = c.F.GetInt()
							if err != nil {
								length = 1
							}
							// we must have some values here, so randomly choose a short length
							req.Values = make([]string, length%3)
						}
						for i := range req.Values {
							l, err = randomLabelPart(c, true)
							if err != nil {
								l = "fuzz"
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
