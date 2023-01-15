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
	"bytes"
	"reflect"
	"fmt"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang/protobuf/proto"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"
	"encoding/hex"
	"strings"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/diff"
	gfh "github.com/AdaLogics/go-fuzz-headers"
)


var (
	globalNonRoundTrippableTypes = sets.NewString(
		"ExportOptions",
		"GetOptions",
		// WatchEvent does not include kind and version and can only be deserialized
		// implicitly (if the caller expects the specific object). The watch call defines
		// the schema by content type, rather than via kind/version included in each
		// object.
		"WatchEvent",
		// ListOptions is now part of the meta group
		"ListOptions",
		// Delete options is only read in metav1
		"DeleteOptions",
	)
	
)

func ExternalTypesViaJSON(data []byte, typeToTest int) {
	codecFactory := serializer.NewCodecFactory(Scheme)
	fuzzCodecFactory = codecFactory

	kinds := Scheme.AllKnownTypes()
	i := 0
	for gvk := range kinds {
		if gvk.Version == runtime.APIVersionInternal || globalNonRoundTrippableTypes.Has(gvk.Kind) {
			return
		}
		if i == typeToTest%len(kinds) {
			roundTripOfExternalType(data, gvk)
		}
		i++
	}
}

func roundTripOfExternalType(data []byte, externalGVK schema.GroupVersionKind) {
	object, err := Scheme.New(externalGVK)
	if err != nil {
		panic(fmt.Sprintf("Couldn't make a %v? %v", externalGVK, err))
	}
	typeAcc, err := apimeta.TypeAccessor(object)
	if err != nil {
		panic(fmt.Sprintf("%q is not a TypeMeta and cannot be tested - add it to nonRoundTrippableInternalTypes: %v", externalGVK, err))
	}

	object, err = fuzzInternalObject(data, object)
	if err != nil {
		return
	}

	typeAcc.SetKind(externalGVK.Kind)
	typeAcc.SetAPIVersion(externalGVK.GroupVersion().String())

	roundTrip(json.NewSerializer(json.DefaultMetaFactory, Scheme, Scheme, false), object)

	// TODO remove this hack after we're past the intermediate steps
	roundTrip(protobuf.NewSerializer(Scheme, Scheme), object)
}

func fuzzInternalObject(data []byte, object runtime.Object) (runtime.Object, error) {
	ff := gfh.NewConsumer(data)
	for i := range customFuncs {
		ff.AddFuncs(customFuncs[i])
	}
	ff.GenerateWithCustom(object)

	j, err := apimeta.TypeAccessor(object)
	if err != nil {
		panic(fmt.Sprintf("Unexpected error %v for %#v\n", err, object))
	}
	j.SetKind("")
	j.SetAPIVersion("")

	return object, nil
}

func roundTrip(codec runtime.Codec, object runtime.Object) {
	printer := spew.ConfigState{DisableMethods: true}
	original := object

	// deep copy the original object
	object = object.DeepCopyObject()
	name := reflect.TypeOf(object).Elem().Name()
	if !apiequality.Semantic.DeepEqual(original, object) {
		fmt.Printf("%v: DeepCopy altered the object, diff: %v\n", name, diff.ObjectReflectDiff(original, object))
		fmt.Printf("%s\n", spew.Sdump(original))
		fmt.Printf("%s\n", spew.Sdump(object))
		panic("not equal")
	}

	// encode (serialize) the deep copy using the provided codec
	data, err := runtime.Encode(codec, object)
	if err != nil {
		return
	}

	// ensure that the deep copy is equal to the original; neither the deep
	// copy or conversion should alter the object
	// TODO eliminate this global
	if !apiequality.Semantic.DeepEqual(original, object) {
		panic(fmt.Sprintf("%v: encode altered the object, diff: %v\n", name, diff.ObjectReflectDiff(original, object)))
		return
	}

	// encode (serialize) a second time to verify that it was not varying
	secondData, err := runtime.Encode(codec, object)
	if err != nil {
		if runtime.IsNotRegisteredError(err) {
			return
		} else {
			panic(fmt.Sprintf("%v: %v (%s)", name, err, printer.Sprintf("%#v", object)))
		}
	}

	// serialization to the wire must be stable to ensure that we don't write twice to the DB
	// when the object hasn't changed.
	if !bytes.Equal(data, secondData) {
		panic(fmt.Sprintf("%v: serialization is not stable: %s", name, printer.Sprintf("%#v", object)))
	}

	// decode (deserialize) the encoded data back into an object
	obj2, err := runtime.Decode(codec, data)
	if err != nil {
		panic(fmt.Sprintf("%v: %v\nCodec: %#v\nData: %s\nSource: %#v\n", name, err, codec, dataAsString(data), printer.Sprintf("%#v", object)))
	}

	// ensure that the object produced from decoding the encoded data is equal
	// to the original object
	if !apiequality.Semantic.DeepEqual(original, obj2) {
		panic(fmt.Sprintf("%v: diff: %v\nCodec: %#v\nSource:\n\n%#v\n\nEncoded:\n\n%s\n\nFinal:\n\n%#v\n", name, diff.ObjectReflectDiff(original, obj2), codec, printer.Sprintf("%#v", original), dataAsString(data), printer.Sprintf("%#v", obj2)))
	}

	// decode the encoded data into a new object (instead of letting the codec
	// create a new object)
	obj3 := reflect.New(reflect.TypeOf(object).Elem()).Interface().(runtime.Object)
	if err := runtime.DecodeInto(codec, data, obj3); err != nil {
		panic(fmt.Sprintf("%v: %v", name, err))
	}

	// special case for kinds which are internal and external at the same time (many in meta.k8s.io are). For those
	// runtime.DecodeInto above will return the external variant and set the APIVersion and kind, while the input
	// object might be internal. Hence, we clear those values for obj3 for that case to correctly compare.
	intAndExt, err := internalAndExternalKind(object)
	if err != nil {
		panic(fmt.Sprintf("%v: %v", name, err))
	}
	if intAndExt {
		typeAcc, err := apimeta.TypeAccessor(object)
		if err != nil {
			panic(fmt.Sprintf("%v: error accessing TypeMeta: %v\n", name, err))

		}
		if len(typeAcc.GetAPIVersion()) == 0 {
			typeAcc, err := apimeta.TypeAccessor(obj3)
			if err != nil {
				panic(fmt.Sprintf("%v: error accessing TypeMeta: %v", name, err))
			}
			typeAcc.SetAPIVersion("")
			typeAcc.SetKind("")
		}
	}

	// ensure that the new runtime object is equal to the original after being
	// decoded into
	//fmt.Println("Here")
	if !apiequality.Semantic.DeepEqual(object, obj3) {
		panic(fmt.Sprintf("%v: diff: %v\nCodec: %#v", name, diff.ObjectReflectDiff(object, obj3), codec))
	}

	// do structure-preserving fuzzing of the deep-copied object. If it shares anything with the original,
	// the deep-copy was actually only a shallow copy. Then original and obj3 will be different after fuzzing.
	// NOTE: we use the encoding+decoding here as an alternative, guaranteed deep-copy to compare against.

	//TODO: Use gfh here
	//fuzzer.ValueFuzz(object)
	if !apiequality.Semantic.DeepEqual(original, obj3) {
		panic(fmt.Sprintf("%v: fuzzing a copy altered the original, diff: %v", name, diff.ObjectReflectDiff(original, obj3)))
	}
}

func internalAndExternalKind(object runtime.Object) (bool, error) {
	kinds, _, err := Scheme.ObjectKinds(object)
	if err != nil {
		return false, err
	}
	internal, external := false, false
	for _, k := range kinds {
		if k.Version == runtime.APIVersionInternal {
			internal = true
		} else {
			external = true
		}
	}
	return internal && external, nil
}

// dataAsString returns the given byte array as a string; handles detecting
// protocol buffers.
func dataAsString(data []byte) string {
	dataString := string(data)
	if !strings.HasPrefix(dataString, "{") {
		dataString = "\n" + hex.Dump(data)
		proto.NewBuffer(make([]byte, 0, 1024)).DebugPrint("decoded object", data)
	}
	return dataString
}