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
	"net/url"

	"time"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"knative.dev/pkg/apis"
)

var (
	Funcs = FuzzerFuncs()
)

// Funcs includes fuzzing funcs for knative.dev/serving types
//
// For other examples see
// https://github.com/kubernetes/apimachinery/blob/master/pkg/apis/meta/fuzzer/fuzzer.go
func FuzzerFuncs() []interface{} {
	return []interface{}{
		func(u *apis.URL, c fuzz.Continue) error {
			var schemeString, hostString, user, p, rawPath, rawQuery string
			var err error
			schemeString, err = c.F.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 50)
			if err != nil {
				schemeString = "fuzz"
			}
			hostString, err = c.F.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 50)
			if err != nil {
				hostString = "fuzz"
			}
			user, err = c.F.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 50)
			if err != nil {
				user = "fuzz"
			}
			p, err = c.F.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 50)
			if err != nil {
				p = "fuzz"
			}
			u.Scheme = schemeString
			u.Host = hostString
			u.User = url.UserPassword(
				user, // username
				p,    // password
			)
			rawPath, err = c.F.GetString()
			if err != nil {
				rawPath = "fuzz"
			}
			rawQuery, err = c.F.GetString()
			if err != nil {
				rawPath = "fuzz"
			}
			u.RawPath = url.PathEscape(rawPath)
			u.RawQuery = url.QueryEscape(rawQuery)
			return nil
		},
	}
}

// FuzzConditions fuzzes the values for the conditions. It doesn't add
// any new condition types
//
// Consumers should initialize their conditions prior to fuzzing them.
// For example:
//
//	func(s *SomeStatus, c fuzz.Continue) {
//	  c.FuzzNoCustom(s) // fuzz the status object
//
//	  // Clear the random fuzzed condition
//	  s.Status.SetConditions(nil)
//
//	  // Fuzz the known conditions except their type value
//	  s.InitializeConditions()
//	  fuzz.Conditions(&s.Status, c)
//	}
func FuzzConditions(accessor apis.ConditionsAccessor, c fuzz.Continue) error {
	conds := accessor.GetConditions()
	for i, cond := range conds {
		// Leave condition.Type untouched
		var str1, str2, str3, str4 string
		var err error
		var timeInt uint64
		str1, err = c.F.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 50)
		if err != nil {
			str1 = "fuzz"
		}
		str2, err = c.F.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 20)
		if err != nil {
			str2 = "fuzz"
		}
		str3, err = c.F.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 50)
		if err != nil {
			str3 = "fuzz"
		}
		str4, err = c.F.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 50)
		if err != nil {
			str4 = "fuzz"
		}
		timeInt, err = c.F.GetUint64()
		if err != nil {
			timeInt = uint64(123)
		}
		cond.Status = corev1.ConditionStatus(str1)
		cond.Severity = apis.ConditionSeverity(str2)
		cond.Message = str3
		cond.Reason = str4

		cond.LastTransitionTime = apis.VolatileTime{Inner: metav1.NewTime(time.Unix(int64(timeInt%(1000*365*24*60*60)), 0))}
		conds[i] = cond
	}
	accessor.SetConditions(conds)
	return nil
}
