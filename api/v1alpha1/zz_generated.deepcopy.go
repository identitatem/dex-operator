//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClaimMappingSpec) DeepCopyInto(out *ClaimMappingSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClaimMappingSpec.
func (in *ClaimMappingSpec) DeepCopy() *ClaimMappingSpec {
	if in == nil {
		return nil
	}
	out := new(ClaimMappingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ConnectorSpec) DeepCopyInto(out *ConnectorSpec) {
	*out = *in
	in.GitHub.DeepCopyInto(&out.GitHub)
	in.LDAP.DeepCopyInto(&out.LDAP)
	in.Microsoft.DeepCopyInto(&out.Microsoft)
	out.OIDC = in.OIDC
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ConnectorSpec.
func (in *ConnectorSpec) DeepCopy() *ConnectorSpec {
	if in == nil {
		return nil
	}
	out := new(ConnectorSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexClient) DeepCopyInto(out *DexClient) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexClient.
func (in *DexClient) DeepCopy() *DexClient {
	if in == nil {
		return nil
	}
	out := new(DexClient)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DexClient) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexClientList) DeepCopyInto(out *DexClientList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]DexClient, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexClientList.
func (in *DexClientList) DeepCopy() *DexClientList {
	if in == nil {
		return nil
	}
	out := new(DexClientList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DexClientList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexClientSpec) DeepCopyInto(out *DexClientSpec) {
	*out = *in
	out.ClientSecretRef = in.ClientSecretRef
	if in.RedirectURIs != nil {
		in, out := &in.RedirectURIs, &out.RedirectURIs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.TrustedPeers != nil {
		in, out := &in.TrustedPeers, &out.TrustedPeers
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexClientSpec.
func (in *DexClientSpec) DeepCopy() *DexClientSpec {
	if in == nil {
		return nil
	}
	out := new(DexClientSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexClientStatus) DeepCopyInto(out *DexClientStatus) {
	*out = *in
	if in.RelatedObjects != nil {
		in, out := &in.RelatedObjects, &out.RelatedObjects
		*out = make([]RelatedObjectReference, len(*in))
		copy(*out, *in)
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexClientStatus.
func (in *DexClientStatus) DeepCopy() *DexClientStatus {
	if in == nil {
		return nil
	}
	out := new(DexClientStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexServer) DeepCopyInto(out *DexServer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexServer.
func (in *DexServer) DeepCopy() *DexServer {
	if in == nil {
		return nil
	}
	out := new(DexServer)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DexServer) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexServerList) DeepCopyInto(out *DexServerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]DexServer, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexServerList.
func (in *DexServerList) DeepCopy() *DexServerList {
	if in == nil {
		return nil
	}
	out := new(DexServerList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DexServerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexServerSpec) DeepCopyInto(out *DexServerSpec) {
	*out = *in
	if in.Connectors != nil {
		in, out := &in.Connectors, &out.Connectors
		*out = make([]ConnectorSpec, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	out.IngressCertificateRef = in.IngressCertificateRef
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexServerSpec.
func (in *DexServerSpec) DeepCopy() *DexServerSpec {
	if in == nil {
		return nil
	}
	out := new(DexServerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DexServerStatus) DeepCopyInto(out *DexServerStatus) {
	*out = *in
	if in.RelatedObjects != nil {
		in, out := &in.RelatedObjects, &out.RelatedObjects
		*out = make([]RelatedObjectReference, len(*in))
		copy(*out, *in)
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DexServerStatus.
func (in *DexServerStatus) DeepCopy() *DexServerStatus {
	if in == nil {
		return nil
	}
	out := new(DexServerStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GitHubConfigSpec) DeepCopyInto(out *GitHubConfigSpec) {
	*out = *in
	out.ClientSecretRef = in.ClientSecretRef
	if in.Orgs != nil {
		in, out := &in.Orgs, &out.Orgs
		*out = make([]Org, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GitHubConfigSpec.
func (in *GitHubConfigSpec) DeepCopy() *GitHubConfigSpec {
	if in == nil {
		return nil
	}
	out := new(GitHubConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GroupSearchSpec) DeepCopyInto(out *GroupSearchSpec) {
	*out = *in
	if in.UserMatchers != nil {
		in, out := &in.UserMatchers, &out.UserMatchers
		*out = make([]UserMatcher, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GroupSearchSpec.
func (in *GroupSearchSpec) DeepCopy() *GroupSearchSpec {
	if in == nil {
		return nil
	}
	out := new(GroupSearchSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LDAPConfigSpec) DeepCopyInto(out *LDAPConfigSpec) {
	*out = *in
	out.RootCARef = in.RootCARef
	if in.RootCAData != nil {
		in, out := &in.RootCAData, &out.RootCAData
		*out = make([]byte, len(*in))
		copy(*out, *in)
	}
	out.BindPWRef = in.BindPWRef
	out.UserSearch = in.UserSearch
	in.GroupSearch.DeepCopyInto(&out.GroupSearch)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LDAPConfigSpec.
func (in *LDAPConfigSpec) DeepCopy() *LDAPConfigSpec {
	if in == nil {
		return nil
	}
	out := new(LDAPConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MicrosoftConfigSpec) DeepCopyInto(out *MicrosoftConfigSpec) {
	*out = *in
	out.ClientSecretRef = in.ClientSecretRef
	if in.Groups != nil {
		in, out := &in.Groups, &out.Groups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MicrosoftConfigSpec.
func (in *MicrosoftConfigSpec) DeepCopy() *MicrosoftConfigSpec {
	if in == nil {
		return nil
	}
	out := new(MicrosoftConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OIDCConfigSpec) DeepCopyInto(out *OIDCConfigSpec) {
	*out = *in
	out.ClientSecretRef = in.ClientSecretRef
	out.ClaimMapping = in.ClaimMapping
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OIDCConfigSpec.
func (in *OIDCConfigSpec) DeepCopy() *OIDCConfigSpec {
	if in == nil {
		return nil
	}
	out := new(OIDCConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Org) DeepCopyInto(out *Org) {
	*out = *in
	if in.Teams != nil {
		in, out := &in.Teams, &out.Teams
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Org.
func (in *Org) DeepCopy() *Org {
	if in == nil {
		return nil
	}
	out := new(Org)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RelatedObjectReference) DeepCopyInto(out *RelatedObjectReference) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RelatedObjectReference.
func (in *RelatedObjectReference) DeepCopy() *RelatedObjectReference {
	if in == nil {
		return nil
	}
	out := new(RelatedObjectReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserMatcher) DeepCopyInto(out *UserMatcher) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserMatcher.
func (in *UserMatcher) DeepCopy() *UserMatcher {
	if in == nil {
		return nil
	}
	out := new(UserMatcher)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserSearchSpec) DeepCopyInto(out *UserSearchSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserSearchSpec.
func (in *UserSearchSpec) DeepCopy() *UserSearchSpec {
	if in == nil {
		return nil
	}
	out := new(UserSearchSpec)
	in.DeepCopyInto(out)
	return out
}
