#include "srsran/asn1/rrc_nr.h"

#include "srsran/common/test_common.h"
#include "srsran/common/test_pcap.h"

#include <iostream>

using namespace asn1;
using namespace asn1::rrc_nr;

inline void hex_dump(uint8_t *buf, uint32_t buf_length) {
    printf("\t");
    for (uint32_t i = 0; i < buf_length; i++) {
        printf("0x%02x ", buf[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n\t");
        }
    }
    printf("\n");
}

int test_enumerated_fuzz() {
    struct types_opts {
        enum options {
            option1, option2, option3, nulltype
        } value;

        const char *to_string() const {
            static const char *options[] = {"option1", "option2", "option3"};
            return convert_enum_idx(options, options::nulltype, value, "types_opts_e");
        }
    };

    enumerated<types_opts> type = types_opts::options::option2;
    TESTASSERT_EQ(type.nof_types, 3);

    for (int i = 0; i < 10; i++) {
        type.fuzz();
        std::cout << type << ", ";
    }
    std::cout << "\n";

    return SRSRAN_SUCCESS;
}

int test_fixed_bitstring_fuzz() {
    fixed_bitstring<39> bs1;
    for (int i = 0; i < 5; i++) {
        bs1.fuzz();
        std::cout << bs1.to_string() << '\n';
    }

    fixed_bitstring<1> bs2;
    for (int i = 0; i < 5; i++) {
        bs2.fuzz();
        std::cout << bs2.to_string() << '\n';
    }
    return SRSRAN_SUCCESS;
}

int test_fuzz_dyn_seq_of() {
    dyn_array<s_nssai_c> s_nssai_list;

    for (int i = 0; i < 3; i++) {
        TESTASSERT(fuzz_dyn_seq_of(s_nssai_list, 1, 8) == SRSASN_SUCCESS);

        json_writer jw;
        if (s_nssai_list.size() > 0) {
            jw.start_array("s-NSSAI-List");
            for (const auto &e1: s_nssai_list) {
                e1.to_json(jw);
            }
            jw.end_array();
        }
        std::cout << jw.to_string() << "\n\n";
    }

    return SRSRAN_SUCCESS;
}

int test_fuzz_dyn_seq_of_with_item_unpacker() {
    bounded_array<uint8_t, 3> mnc;
    for (int i = 0; i < 5; i++) {
        TESTASSERT(fuzz_dyn_seq_of(mnc, 2, 3, integer_packer<uint8_t>(0, 9)) == SRSASN_SUCCESS);
        hex_dump(mnc.data(), mnc.size());
    }

    return SRSRAN_SUCCESS;
}

int test_fuzz_fixed_seq_of_with_item_unpacker() {
    std::array<uint8_t, 3> mcc;
    for (int i = 0; i < 5; i++) {
        TESTASSERT(fuzz_fixed_seq_of(&(mcc)[0], mcc.size(), integer_packer<uint8_t>(0, 9)) == SRSASN_SUCCESS);
        hex_dump(mcc.data(), mcc.size());
    }

    return SRSRAN_SUCCESS;
}

int test_rrc_setup_request_fuzz() {
//    rrc_setup_request_s setup_request;

    for (int i = 0; i < 5; i++) {
        rrc_setup_request_s setup_request;
        TESTASSERT(setup_request.fuzz() == SRSASN_SUCCESS);

        srsran::unique_byte_buffer_t buf = srsran::make_byte_buffer();
        TESTASSERT(buf != nullptr);
        bit_ref bref(buf->data(), buf->get_tailroom());
        TESTASSERT(setup_request.pack(bref) == SRSASN_SUCCESS);

        json_writer jw;
        setup_request.to_json(jw);
        std::cout << jw.to_string() << "\n\n";
    }

    return SRSRAN_SUCCESS;
}

int test_rrc_setup_complete_fuzz() {
    rrc_setup_complete_s setup_complete;

    for (int i = 0; i < 5; i++) {
        TESTASSERT(setup_complete.fuzz() == SRSASN_SUCCESS);

        srsran::unique_byte_buffer_t buf = srsran::make_byte_buffer();
        TESTASSERT(buf != nullptr);
        bit_ref bref(buf->data(), buf->get_tailroom());
        TESTASSERT(setup_complete.pack(bref) == SRSASN_SUCCESS);

        json_writer jw;
        setup_complete.to_json(jw);
        std::cout << jw.to_string() << "\n\n";
    }

    return SRSRAN_SUCCESS;
}

int main() {
    srslog::init();
    srsran::console("Testing RRC NR fuzzing\n");

    srsran::mac_pcap pcap;
    pcap.open("/tmp/srsran_asn1_rrc_nr_fuzz_test.pcap");

    // Test utilities
    TESTASSERT(test_enumerated_fuzz() == SRSRAN_SUCCESS);
    TESTASSERT(test_fixed_bitstring_fuzz() == SRSRAN_SUCCESS);
    TESTASSERT(test_fuzz_dyn_seq_of() == SRSRAN_SUCCESS);
    TESTASSERT(test_fuzz_dyn_seq_of_with_item_unpacker() == SRSRAN_SUCCESS);
    TESTASSERT(test_fuzz_fixed_seq_of_with_item_unpacker() == SRSRAN_SUCCESS);

    // Test messages
    TESTASSERT(test_rrc_setup_request_fuzz() == SRSRAN_SUCCESS);
    TESTASSERT(test_rrc_setup_complete_fuzz() == SRSRAN_SUCCESS);

    pcap.close();
    srslog::flush();

    return SRSRAN_SUCCESS;
}
