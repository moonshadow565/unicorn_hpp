#include <catch2/catch_test_macros.hpp>
#include <unicorn.hpp>

TEST_CASE("example_x86", "[x86][example]") {
    auto uc = uc::EngineOwner(uc::X86::MODE_32, "Creating example uc engine!");

    auto uc2 = uc::EngineOwner(uc::X86::MODE_32, "Creating example uc engine!");

    REQUIRE(uc != uc2);

    SECTION("Registers") {
        *uc->reg.eax = 10;
        uint32_t value = *uc->reg.eax;
        REQUIRE(value == 10);

        SECTION("Bitcasting register") {
            uc->reg.eax.write_bitcast<float>(10.5);
            float value_float = uc->reg.eax.read_bitcast<float>();
            REQUIRE(value_float == 10.5);
        }
    }

    SECTION("Hooking") {
        SECTION("Hook using member function pointer") {
            struct Object {
                bool was_called = false;
                void on_sysenter(uc::EngineHandle<uc::X86> uc) {
                    // do something here
                    was_called = true;
                }
            };
            Object object = {};
            if (auto result = uc->hook.add_insn_sysenter<&Object::on_sysenter>(uc::mem::Range(), &object)) {
                // hook is automatically released at the end of scope
            }
        }

        SECTION("Hook using a lambda with user data") {
            std::uint32_t user_data = 0;
            constexpr auto callback = [](std::uint32_t* user_data, uc::EngineHandle<uc::X86> uc, std::uint32_t port) {
                // Store port in userdata
                *user_data = port;
            };
            uc::Result<uc::Hook> result = uc->hook.add_interupt<+callback>(uc::mem::Range(), &user_data);

            // Convert managed hook into unmanaged one
            uc::HookID hook_id = (uc::HookID)std::move(*result);

            // Expect will throw when Result had any errors.
            uc->hook.del(hook_id).expect();
        }

        SECTION("Hook using compiletime function pointer") {
            constexpr auto callback = [](uc::EngineHandle<uc::X86> uc) -> bool { return false; };

            // Converting Result<Hook> into Result<HookID>
            uc::Result<uc::HookID> hook_id = uc->hook.add_insn_invalid<+callback>(uc::mem::Range()).into<uc::HookID>();

            // Ensure our hook succeded...
            REQUIRE(hook_id == uc::Error::OK);

            // We don't care to clean up hook manually here since it doesn't reference any user data that may still be
            // in scope.
        }
    }

    SECTION("Memory") {
        constexpr uc::mem::Address address = 0x10'000;
        constexpr std::size_t size = 0x1000;

        std::vector<char> data = {0x11, 0x22, 0x33, 0x44};
        uc->mem.map(address, size, uc::mem::PROT_ALL).expect();
        uc->mem.write(address, data.data(), data.size()).expect();

        SECTION("Access as bitcasted value") {
            uint32_t value = 0;
            // Results can be checked out into value while returning any possible errors.
            REQUIRE(uc->mem.read_bitcast<uint32_t>(address).check_out(value) == uc::error::OK);
            REQUIRE(value == 0x44'33'22'11);
        }

        uc->mem.unmap(address, size).expect();
    }

    SECTION("Errors") {
        try {
            uc->mem.map(0, 0x10, uc::mem::PROT_ALL).expect("Mapping some memory.");
        } catch (uc::Exception exception) {
            REQUIRE(std::string{exception.what()} == "Invalid argument (UC_ERR_ARG)");
            REQUIRE(std::string{exception.why} == "Mapping some memory.");
        }
    }
}
