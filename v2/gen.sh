#!/bin/bash

protoc \
    -I ./proto \
    --proto_path=./proto \
    --go_out=./gen \
    --go_opt=paths=source_relative \
    --experimental_allow_proto3_optional \
    common.proto \
    certificate.proto \
    certificate_request.proto \
    subject.proto \
    extension_2.5.29.15_key_usage.proto \
    extension_2.5.29.16_private_key_usage_period.proto \
    extension_2.5.29.17_subject_alternative_name.proto \
    extension_2.5.29.19_basic_constraints.proto \
    extension_2.5.29.37_extended_key_usage.proto
