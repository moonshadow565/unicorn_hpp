#include <catch2/catch_test_macros.hpp>
#include <unicorn.hpp>

constexpr uint32_t CODE_START = 0x1000;
constexpr uint32_t CODE_CAP = 0x4000;

TEST_CASE("x86_reg_deref", "[x86][setup]") {
    auto uc = uc::EngineOwner(uc::X86::MODE_32);

    *uc->reg.eax = 10;
    *uc->reg.ecx = *uc->reg.eax;
    uint32_t value = *uc->reg.cx;
    REQUIRE(value == 10);
    REQUIRE(*uc->reg.eax == 10);
    REQUIRE(*uc->reg.eax == *uc->reg.ecx);
}

TEST_CASE("x86_setup", "[x86][setup]") {
    char const CODE[] = "\xCC";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, sizeof(CODE) - 1) == uc::error::OK);
}

TEST_CASE("x86_invalid_mem_read", "[x86][mem]") {
    char const CODE[] = "\x8b\x0d\xaa\xaa\xaa\xaa";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);
    auto result = uc->emu.start(CODE_START, CODE_START + CODE_SIZE);
    REQUIRE(result.error == uc::error::ERR_READ_UNMAPPED);
}

TEST_CASE("x86_invalid_mem_write", "[x86][mem]") {
    char const CODE[] = "\x89\x0d\xaa\xaa\xaa\xaa";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);
    auto result = uc->emu.start(CODE_START, CODE_START + CODE_SIZE);
    REQUIRE(result.error == uc::error::ERR_WRITE_UNMAPPED);
}

TEST_CASE("x86_invalid_mem_fetch", "[x86][mem]") {
    char const CODE[] = "\xe9\xe9\xee\xee\xee";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);
    auto result = uc->emu.start(CODE_START, CODE_START + CODE_SIZE);
    REQUIRE(result.error == uc::error::ERR_FETCH_UNMAPPED);
}

TEST_CASE("x86_inc_dec_pxor", "[x86][run]") {
    char const CODE[] = "\x41\x4a\x66\x0f\xef\xc1";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);

    uint32_t r_ecx = 0x1234;
    uint32_t r_edx = 0x7890;
    uc::mem::U128 r_xmm0 = {0x08090a0b0c0d0e0f, 0x0001020304050607};
    uc::mem::U128 r_xmm1 = {0x8090a0b0c0d0e0f0, 0x0010203040506070};

    uc->reg.ecx.write(r_ecx);
    uc->reg.edx.write(r_edx);
    uc->reg.xmm0.write(r_xmm0);
    uc->reg.xmm1.write(r_xmm1);

    REQUIRE(uc->emu.start(CODE_START, CODE_START + CODE_SIZE) == uc::error::OK);

    r_ecx = uc->reg.ecx.read();
    r_edx = uc->reg.edx.read();
    r_xmm0 = uc->reg.xmm0.read();
    r_xmm1 = uc->reg.xmm1.read();

    REQUIRE(r_ecx == 0x1235);
    REQUIRE(r_edx == 0x788f);
    REQUIRE(r_xmm0 == uc::mem::U128{0x8899aabbccddeeff, 0x0011223344556677});
}

TEST_CASE("x86_relative_jump", "[x86][run]") {
    char const CODE[] = "\xeb\x02\x90\x90\x90\x90\x90\x90";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);

    uint32_t r_eip = 0;

    REQUIRE(uc->emu.start(CODE_START, CODE_START + 4) == uc::error::OK);

    r_eip = uc->reg.eip.read();

    REQUIRE(r_eip == CODE_START + 4);
}

TEST_CASE("x86_loop", "[x86][run]") {
    using namespace std::chrono_literals;

    char const CODE[] = "\x41\x4a\xeb\xfe";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);

    uint32_t r_ecx = 0x1234;
    uint32_t r_edx = 0x7890;

    uc->reg.ecx.write(r_ecx);
    uc->reg.edx.write(r_edx);

    REQUIRE(uc->emu.start(CODE_START, CODE_START + CODE_SIZE, 100ms) == uc::error::OK);

    r_ecx = uc->reg.ecx.read();
    r_edx = uc->reg.edx.read();

    REQUIRE(r_ecx == 0x1235);
    REQUIRE(r_edx == 0x788F);
}

TEST_CASE("x86_16_add", "[x86][run]") {
    char const CODE[] = "\x00\x00";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    uint16_t r_ax = 7;
    uint16_t r_bx = 5;
    uint16_t r_si = 6;
    uint8_t result = 0;

    auto uc = uc::EngineOwner(uc::X86::MODE_16);
    REQUIRE(uc->mem.map(0, 0x1000, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);

    uc->reg.ax.write(r_ax);
    uc->reg.bx.write(r_bx);
    uc->reg.si.write(r_si);

    REQUIRE(uc->emu.start(CODE_START, CODE_START + CODE_SIZE) == uc::error::OK);

    REQUIRE(uc->mem.read_bitcast<uint8_t>(r_bx + r_si).check_out(result) == uc::error::OK);

    REQUIRE(result == 7);
}

TEST_CASE("x86_smc_xor", "[x86][run]") {
    char const CODE[] = "\x31\x47\x03\x13\x8b\xa9\x3e";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    uint32_t r_edi = CODE_START;
    uint32_t r_eax = 0xbc4177e6;
    uint32_t result = 0;

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);

    uc->reg.edi.write(r_edi);
    uc->reg.eax.write(r_eax);

    REQUIRE(uc->emu.start(CODE_START, CODE_START + 3).error == uc::error::OK);

    REQUIRE(uc->mem.read_bitcast<uint32_t>(CODE_START + 3).check_out(result) == uc::error::OK);

    REQUIRE(result == (0x3ea98b13 ^ 0xbc4177e6));
}

TEST_CASE("x86_reg_save", "[x86][ctx]") {
    char const CODE[] = "\x40";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    uint32_t r_eax = 1;

    auto ctx = uc::Context<uc::X86>();
    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);

    uc->reg.eax.write(r_eax);

    REQUIRE(ctx.save(uc) == uc::error::OK);

    REQUIRE(uc->emu.start(CODE_START, CODE_START + CODE_SIZE) == uc::error::OK);

    REQUIRE(ctx.restore(uc) == uc::error::OK);

    r_eax = uc->reg.eax.read();

    REQUIRE(r_eax == 1);
}

TEST_CASE("x86_hook_mem_all", "[x86][hook]") {
    char const CODE[] = "\xb8\xef\xbe\xad\xde\xa3\x00\x80\x00\x00\xa1\x00\x00\x01\x00";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    struct Data {
        using Item = std::tuple<uc::mem::Access, uc::mem::Address, std::size_t, uc::mem::Value>;
        std::vector<Item> items;
        bool callback(uc::EngineHandle<uc::X86> uc,
                      uc::mem::Access access,
                      uc::mem::Address address,
                      std::size_t size,
                      uc::mem::Value value) {
            items.emplace_back(access, address, size, value);
            if (access == uc::mem::ACCESS_READ_UNMAPPED) {
                uc->mem.map(address, 0x1000, uc::mem::PROT_ALL).expect();
            }
            return true;
        }
    } data{};

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);
    REQUIRE(uc->mem.map(0x8000, 0x1000, uc::mem::PROT_ALL) == uc::error::OK);
    auto hook = uc->hook.add_mem<&Data::callback>(uc::mem::Range(), uc::mem::HOOK_ALL, &data);
    REQUIRE(hook == uc::error::OK);
    REQUIRE(uc->emu.start(CODE_START, CODE_START + CODE_SIZE) == uc::error::OK);

    REQUIRE(data.items.size() == 3);
    REQUIRE(data.items[0] == std::tuple{uc::mem::ACCESS_WRITE, 0x8000, 4, 0xdeadbeef});
    REQUIRE(data.items[1] == std::tuple{uc::mem::ACCESS_READ_UNMAPPED, 0x10000, 4, 0});
    REQUIRE(data.items[2] == std::tuple{uc::mem::ACCESS_READ, 0x10000, 4, 0});
}

// TEST_CASE("x86_missing_code", "[x86][hook]") {
//     // NOTE: original test uses unmaped memory which messes with whatever catch2 does...
//     // We use memory without permissions instead
//     uint32_t r_ecx = 0x1234;
//     uint32_t r_edx = 0x7890;

//    auto uc = uc::EngineOwner(uc::X86::MODE_32);

//    uc->reg.ecx.write(r_ecx);
//    uc->reg.edx.write(r_edx);

//    constexpr auto callback = [](uc::EngineHandle<uc::X86> uc,
//                                 uc::mem::Access access,
//                                 uc::mem::Address address,
//                                 std::size_t size,
//                                 uc::mem::Value value) {
//        char const CODE[] = "\x41\x4a";
//        constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

//        uc->mem.write(CODE_START, CODE, CODE_SIZE).expect();
//        uc->mem.protect(CODE_START, CODE_CAP, uc::mem::PROT_ALL).expect();

//        return true;
//    };

//    uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_NONE).expect();

//    auto hook = uc->hook.add_mem<callback>(uc::mem::Range(), uc::mem::HOOK_PROT) == uc::error::OK);
//    REQUIRE(uc->emu.start(CODE_START, CODE_START + 2) == uc::error::OK);

//    r_ecx = uc->reg.ecx.read();
//    r_edx = uc->reg.edx.read();

//    REQUIRE(r_ecx == 0x1235);
//    REQUIRE(r_edx == 0x788f);
//}

TEST_CASE("x86_invalid_mem_read_stop", "[x86][hook]") {
    char const CODE[] = "\x40\x8b\x1d\x00\x00\x10\x00\x42";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    uint32_t r_eax = 0x1234;
    uint32_t r_edx = 0x5678;
    uint32_t r_eip = 0;

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);

    uc->reg.eax.write(r_eax);
    uc->reg.edx.write(r_edx);

    constexpr auto callback = [](uc::EngineHandle<uc::X86> uc,
                                 uc::mem::Access access,
                                 uc::mem::Address address,
                                 std::size_t size,
                                 uc::mem::Value value) { return false; };

    auto hook = uc->hook.add_mem<+callback>(uc::mem::Range(), uc::mem::HOOK_READ);
    REQUIRE(hook == uc::error::OK);
    auto const result = uc->emu.start(CODE_START, CODE_START + CODE_SIZE);
    REQUIRE(result.error == uc::error::ERR_READ_UNMAPPED);

    r_eax = uc->reg.eax.read();
    r_edx = uc->reg.edx.read();
    r_eip = uc->reg.eip.read();

    REQUIRE(r_eax == 0x1235);
    REQUIRE(r_edx == 0x5678);
    REQUIRE(r_eip == CODE_START + 1);
}

TEST_CASE("x86_hook_in", "[x86][hook]") {
    char const CODE[] = "\xe5\x10";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;
    struct Data {
        std::uint32_t port = {};
        std::size_t size = {};
        std::uint32_t callback(uc::EngineHandle<uc::X86> uc, std::uint32_t port, std::size_t size) {
            this->port = port;
            this->size = size;
            return 0;
        }
    } data{};

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);
    auto hook = uc->hook.add_insn_in<&Data::callback>(uc::mem::Range(CODE_START, CODE_START + CODE_SIZE), &data);
    REQUIRE(hook == uc::error::OK);
    REQUIRE(uc->emu.start(CODE_START, CODE_START + CODE_SIZE) == uc::error::OK);

    REQUIRE(data.port == 0x10);
    REQUIRE(data.size == 0x04);
}

TEST_CASE("x86_hook_out", "[x86][hook]") {
    char const CODE[] = "\xb0\x32\xe6\x46";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;
    struct Data {
        std::uint32_t port = {};
        std::size_t size = {};
        std::uint32_t value = {};
        void callback(uc::EngineHandle<uc::X86> uc, std::uint32_t port, std::size_t size, std::uint32_t value) {
            this->port = port;
            this->size = size;
            this->value = value;
        }
    } data{};

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);
    auto hook = uc->hook.add_insn_out<&Data::callback>(uc::mem::Range(CODE_START, CODE_START + CODE_SIZE), &data);
    REQUIRE(hook == uc::error::OK);
    REQUIRE(uc->emu.start(CODE_START, CODE_START + CODE_SIZE) == uc::error::OK);

    REQUIRE(data.port == 0x46);
    REQUIRE(data.size == 0x01);
    REQUIRE(data.value == 0x32);
}

TEST_CASE("x86_64_syscall", "[x86][hook]") {
    char const CODE[] = "\x0f\x05";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    uint64_t r_rax = 0;

    auto uc = uc::EngineOwner(uc::X86::MODE_64);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);

    uc->reg.rax.write(r_rax);

    constexpr auto callback = [](uc::EngineHandle<uc::X86> uc) {
        uint64_t r_rax = uc->reg.rax.read();
        uc->reg.rax.write(0x200);
    };

    auto hook = uc->hook.add_insn_syscall<+callback>(uc::mem::Range());
    REQUIRE(hook == uc::error::OK);
    REQUIRE(uc->emu.start(CODE_START, CODE_START + CODE_SIZE) == uc::error::OK);

    r_rax = uc->reg.rax.read();

    REQUIRE(r_rax == 0x200);
}

TEST_CASE("x86_sysenter", "[x86][hook]") {
    char const CODE[] = "\x0F\x34";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    uint32_t r_eax = 0x100;

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);

    uc->reg.eax.write(r_eax);

    constexpr auto callback = [](uc::EngineHandle<uc::X86> uc) {
        uint32_t r_eax = uc->reg.eax.read();
        uc->reg.eax.write(0x200);
    };

    auto hook = uc->hook.add_insn_sysenter<+callback>(uc::mem::Range());
    REQUIRE(hook == uc::error::OK);
    REQUIRE(uc->emu.start(CODE_START, CODE_START + CODE_SIZE) == uc::error::OK);

    r_eax = uc->reg.eax.read();

    REQUIRE(r_eax == 0x200);
}

TEST_CASE("x86_hook_cpuid", "[x86][hook]") {
    char const CODE[] = "\x40\x0F\xA2";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    uint32_t r_eax = 0;

    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);

    uc->reg.eax.write(r_eax);

    constexpr auto callback = [](uc::EngineHandle<uc::X86> uc) -> bool {
        uint32_t r_eax = uc->reg.eax.read();
        uc->reg.eax.write(0x200);
        return true;
    };

    auto hook = uc->hook.add_insn_cpuid<+callback>(uc::mem::Range());
    REQUIRE(hook == uc::error::OK);
    REQUIRE(uc->emu.start(CODE_START, CODE_START + CODE_SIZE) == uc::error::OK);

    r_eax = uc->reg.eax.read();

    REQUIRE(r_eax == 0x200);
}

TEST_CASE("x86_x87_fnstenv", "[x86][hook]") {
    constexpr char const CODE[] = "\xd9\xd0\xd9\x30\xd9\x00\xd9\x30";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;
    constexpr std::uint32_t BASE = CODE_START + 3 * CODE_CAP;

    uint32_t last_eip = 0;
    uint32_t fnstenv[7] = {};

    constexpr auto callback =
        [](uint32_t* last_eip, uc::EngineHandle<uc::X86> uc, uc::mem::Address address, std::size_t size) {
            if (address == CODE_START + 4) {
                *last_eip = uc->reg.eip.read();
                uint32_t eax = uc->reg.eax.read();
                uint32_t fnstenv[7] = {};
                uc->mem.read(eax, fnstenv, 7).expect();
                assert(fnstenv[3] == 0);
            }
        };

    auto uc = uc::EngineOwner(uc::X86::MODE_32);

    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);

    REQUIRE(uc->mem.map(BASE, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    uc->reg.eax.write(BASE);

    auto hook = uc->hook.add_code<+callback>(uc::mem::Range(), &last_eip);
    REQUIRE(hook == uc::error::OK);

    REQUIRE(uc->emu.start(CODE_START, CODE_START + CODE_SIZE) == uc::error::OK);

    REQUIRE(uc->mem.read(BASE, fnstenv, sizeof(fnstenv)) == uc::error::OK);
    REQUIRE(fnstenv[3] == last_eip);
}

TEST_CASE("x86_mmio", "[x86][hook]") {
    constexpr char const CODE[] = "\x89\x0d\x04\x00\x02\x00\x8b\x0d\x04\x00\x02\x00";
    constexpr std::size_t CODE_SIZE = sizeof(CODE) - 1;

    struct MMIO {
        uc::mem::Value read(uc::EngineHandle<uc::X86> uc, uc::mem::Address offset, std::size_t size) {
            REQUIRE(offset == 4);
            REQUIRE(size == 4);
            return 0x19260817;
        }
        void write(uc::EngineHandle<uc::X86> uc, uc::mem::Address offset, std::size_t size, uc::mem::Value value) {
            REQUIRE(offset == 4);
            REQUIRE(size == 4);
            REQUIRE(value == 0xdeadbeef);
        };
    } mmio{};

    uint32_t r_ecx = 0xdeadbeef;
    auto uc = uc::EngineOwner(uc::X86::MODE_32);
    REQUIRE(uc->mem.map(CODE_START, CODE_CAP, uc::mem::PROT_ALL) == uc::error::OK);
    REQUIRE(uc->mem.write(CODE_START, CODE, CODE_SIZE) == uc::error::OK);

    uc->reg.ecx.write(r_ecx);
    REQUIRE(uc->mem.map_mmio_rw<&MMIO::read, &MMIO::write>(0x20000, 0x1000, &mmio) == uc::error::OK);

    REQUIRE(uc->emu.start(CODE_START, CODE_START + CODE_SIZE) == uc::error::OK);

    r_ecx = uc->reg.ecx.read();

    REQUIRE(r_ecx == 0x19260817);
}

TEST_CASE("x86_mmio_uc_mem_rw", "[x86][hook]") {
    struct MMIO {
        uc::mem::Value read(uc::EngineHandle<uc::X86> uc, uc::mem::Address offset, std::size_t size) {
            REQUIRE(offset == 8);
            REQUIRE(size == 4);
            return 0x19260817;
        }
        void write(uc::EngineHandle<uc::X86> uc, uc::mem::Address offset, std::size_t size, uc::mem::Value value) {
            REQUIRE(offset == 4);
            REQUIRE(size == 4);
            REQUIRE(value == 0xdeadbeef);
        };
    } mmio{};

    auto uc = uc::EngineOwner(uc::X86::MODE_32);

    REQUIRE(uc->mem.map_mmio_rw<&MMIO::read, &MMIO::write>(0x20000, 0x1000, &mmio) == uc::error::OK);

    uint32_t value = 0xdeadbeef;

    REQUIRE(uc->mem.write_bitcast<uint32_t>(0x20004, value) == uc::error::OK);
    REQUIRE(uc->mem.read_bitcast<uint32_t>(0x20008).check_out(value) == uc::error::OK);

    REQUIRE(value == 0x19260817);
}

// 3
