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
	//"math/rand"
	"net/url"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	corev1 "k8s.io/api/core/v1"
	//"k8s.io/apimachinery/pkg/api/apitesting/fuzzer"
	//"k8s.io/apimachinery/pkg/runtime/serializer"
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
			schemeString, err := c.F.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 50)
			if err != nil {
				return err
			}
			hostString, err := c.F.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 50)
			if err != nil {
				return err
			}
			user, err := c.F.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 50)
			if err != nil {
				return err
			}
			p, err := c.F.GetStringFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 50)
			if err != nil {
				return err
			}
			u.Scheme = schemeString
			u.Host = hostString
			u.User = url.UserPassword(
				user, // username
				p,    // password
			)
			rawPath, err := c.F.GetString()
			if err != nil {
				return err
			}
			rawQuery, err := c.F.GetString()
			if err != nil {
				return err
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
		str1, err := c.F.GetString()
		if err != nil {
			return err
		}
		str2, err := c.F.GetString()
		if err != nil {
			return err
		}
		str3, err := c.F.GetString()
		if err != nil {
			return err
		}
		str4, err := c.F.GetString()
		if err != nil {
			return err
		}
		cond.Status = corev1.ConditionStatus(str1)
		cond.Severity = apis.ConditionSeverity(str2)
		cond.Message = str3
		cond.Reason = str4
		c.F.GenerateStruct(&cond.LastTransitionTime)
		conds[i] = cond
	}
	accessor.SetConditions(conds)
	return nil
}
