// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v3.12.4
// source: certificate_request.proto

package gen

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type CertificateSigningRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BasicConstraints       *ExtensionBasicConstraints       `protobuf:"bytes,1,opt,name=basic_constraints,json=basicConstraints,proto3" json:"basic_constraints,omitempty"`
	Subject                *Subject                         `protobuf:"bytes,2,opt,name=subject,proto3" json:"subject,omitempty"`
	SubjectAlternativeName *ExtensionSubjectAlternativeName `protobuf:"bytes,3,opt,name=subject_alternative_name,json=subjectAlternativeName,proto3" json:"subject_alternative_name,omitempty"`
	KeyUsages              []KeyUsage                       `protobuf:"varint,4,rep,packed,name=key_usages,json=keyUsages,proto3,enum=KeyUsage" json:"key_usages,omitempty"`
	ExtendedKeyUsages      []ExtendedKeyUsage               `protobuf:"varint,5,rep,packed,name=extended_key_usages,json=extendedKeyUsages,proto3,enum=ExtendedKeyUsage" json:"extended_key_usages,omitempty"`
}

func (x *CertificateSigningRequest) Reset() {
	*x = CertificateSigningRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_certificate_request_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CertificateSigningRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CertificateSigningRequest) ProtoMessage() {}

func (x *CertificateSigningRequest) ProtoReflect() protoreflect.Message {
	mi := &file_certificate_request_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CertificateSigningRequest.ProtoReflect.Descriptor instead.
func (*CertificateSigningRequest) Descriptor() ([]byte, []int) {
	return file_certificate_request_proto_rawDescGZIP(), []int{0}
}

func (x *CertificateSigningRequest) GetBasicConstraints() *ExtensionBasicConstraints {
	if x != nil {
		return x.BasicConstraints
	}
	return nil
}

func (x *CertificateSigningRequest) GetSubject() *Subject {
	if x != nil {
		return x.Subject
	}
	return nil
}

func (x *CertificateSigningRequest) GetSubjectAlternativeName() *ExtensionSubjectAlternativeName {
	if x != nil {
		return x.SubjectAlternativeName
	}
	return nil
}

func (x *CertificateSigningRequest) GetKeyUsages() []KeyUsage {
	if x != nil {
		return x.KeyUsages
	}
	return nil
}

func (x *CertificateSigningRequest) GetExtendedKeyUsages() []ExtendedKeyUsage {
	if x != nil {
		return x.ExtendedKeyUsages
	}
	return nil
}

var File_certificate_request_proto protoreflect.FileDescriptor

var file_certificate_request_proto_rawDesc = []byte{
	0x0a, 0x19, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x5f, 0x72, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0d, 0x73, 0x75, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x23, 0x65, 0x78, 0x74, 0x65,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x32, 0x2e, 0x35, 0x2e, 0x32, 0x39, 0x2e, 0x31, 0x35, 0x5f,
	0x6b, 0x65, 0x79, 0x5f, 0x75, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x32, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x32, 0x2e, 0x35, 0x2e, 0x32,
	0x39, 0x2e, 0x31, 0x37, 0x5f, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x61, 0x6c, 0x74,
	0x65, 0x72, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x2b, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x32,
	0x2e, 0x35, 0x2e, 0x32, 0x39, 0x2e, 0x31, 0x39, 0x5f, 0x62, 0x61, 0x73, 0x69, 0x63, 0x5f, 0x63,
	0x6f, 0x6e, 0x73, 0x74, 0x72, 0x61, 0x69, 0x6e, 0x74, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x2c, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x32, 0x2e, 0x35, 0x2e,
	0x32, 0x39, 0x2e, 0x33, 0x37, 0x5f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x5f, 0x6b,
	0x65, 0x79, 0x5f, 0x75, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd1,
	0x02, 0x0a, 0x19, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x53, 0x69,
	0x67, 0x6e, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x47, 0x0a, 0x11,
	0x62, 0x61, 0x73, 0x69, 0x63, 0x5f, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x72, 0x61, 0x69, 0x6e, 0x74,
	0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x73,
	0x69, 0x6f, 0x6e, 0x42, 0x61, 0x73, 0x69, 0x63, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x72, 0x61, 0x69,
	0x6e, 0x74, 0x73, 0x52, 0x10, 0x62, 0x61, 0x73, 0x69, 0x63, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x72,
	0x61, 0x69, 0x6e, 0x74, 0x73, 0x12, 0x22, 0x0a, 0x07, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74,
	0x52, 0x07, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x5a, 0x0a, 0x18, 0x73, 0x75, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x5f, 0x61, 0x6c, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65,
	0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x45, 0x78,
	0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x41, 0x6c,
	0x74, 0x65, 0x72, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x52, 0x16, 0x73,
	0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x41, 0x6c, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x74, 0x69, 0x76,
	0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x28, 0x0a, 0x0a, 0x6b, 0x65, 0x79, 0x5f, 0x75, 0x73, 0x61,
	0x67, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x09, 0x2e, 0x4b, 0x65, 0x79, 0x55,
	0x73, 0x61, 0x67, 0x65, 0x52, 0x09, 0x6b, 0x65, 0x79, 0x55, 0x73, 0x61, 0x67, 0x65, 0x73, 0x12,
	0x41, 0x0a, 0x13, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x5f, 0x6b, 0x65, 0x79, 0x5f,
	0x75, 0x73, 0x61, 0x67, 0x65, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x11, 0x2e, 0x45,
	0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x4b, 0x65, 0x79, 0x55, 0x73, 0x61, 0x67, 0x65, 0x52,
	0x11, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x4b, 0x65, 0x79, 0x55, 0x73, 0x61, 0x67,
	0x65, 0x73, 0x42, 0x16, 0x5a, 0x14, 0x70, 0x6c, 0x61, 0x79, 0x67, 0x72, 0x6f, 0x75, 0x6e, 0x64,
	0x2f, 0x70, 0x61, 0x72, 0x73, 0x65, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_certificate_request_proto_rawDescOnce sync.Once
	file_certificate_request_proto_rawDescData = file_certificate_request_proto_rawDesc
)

func file_certificate_request_proto_rawDescGZIP() []byte {
	file_certificate_request_proto_rawDescOnce.Do(func() {
		file_certificate_request_proto_rawDescData = protoimpl.X.CompressGZIP(file_certificate_request_proto_rawDescData)
	})
	return file_certificate_request_proto_rawDescData
}

var file_certificate_request_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_certificate_request_proto_goTypes = []interface{}{
	(*CertificateSigningRequest)(nil),       // 0: CertificateSigningRequest
	(*ExtensionBasicConstraints)(nil),       // 1: ExtensionBasicConstraints
	(*Subject)(nil),                         // 2: Subject
	(*ExtensionSubjectAlternativeName)(nil), // 3: ExtensionSubjectAlternativeName
	(KeyUsage)(0),                           // 4: KeyUsage
	(ExtendedKeyUsage)(0),                   // 5: ExtendedKeyUsage
}
var file_certificate_request_proto_depIdxs = []int32{
	1, // 0: CertificateSigningRequest.basic_constraints:type_name -> ExtensionBasicConstraints
	2, // 1: CertificateSigningRequest.subject:type_name -> Subject
	3, // 2: CertificateSigningRequest.subject_alternative_name:type_name -> ExtensionSubjectAlternativeName
	4, // 3: CertificateSigningRequest.key_usages:type_name -> KeyUsage
	5, // 4: CertificateSigningRequest.extended_key_usages:type_name -> ExtendedKeyUsage
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_certificate_request_proto_init() }
func file_certificate_request_proto_init() {
	if File_certificate_request_proto != nil {
		return
	}
	file_subject_proto_init()
	file_extension_2_5_29_15_key_usage_proto_init()
	file_extension_2_5_29_17_subject_alternative_name_proto_init()
	file_extension_2_5_29_19_basic_constraints_proto_init()
	file_extension_2_5_29_37_extended_key_usage_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_certificate_request_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CertificateSigningRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_certificate_request_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_certificate_request_proto_goTypes,
		DependencyIndexes: file_certificate_request_proto_depIdxs,
		MessageInfos:      file_certificate_request_proto_msgTypes,
	}.Build()
	File_certificate_request_proto = out.File
	file_certificate_request_proto_rawDesc = nil
	file_certificate_request_proto_goTypes = nil
	file_certificate_request_proto_depIdxs = nil
}
