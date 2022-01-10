#ifndef UNICORN_HPP
#define UNICORN_HPP
#ifdef UNICORN_ENGINE_H
#    pragma error "This header can not be included after unicorn.h"
#endif

#include <array>
#include <chrono>
#include <exception>
#include <functional>
#include <type_traits>
#include <utility>
#include <version>

// Used by unicorn, we have to include it before unicorn does
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

//! @brief Check if we need std::source_location
#ifndef UNCIRON_HPP_DISABLE_LOCATION
#    ifndef __cpp_lib_source_location
#        define UNCIRON_HPP_DISABLE_LOCATION 1
#    else
#        include <source_location>
#    endif
#endif

//! Helper macro for enabling enum bit ops
#define UNICORN_HPP_IMPL_FLAGS(EnumT)                                                                           \
    constexpr EnumT operator|(EnumT lhs, EnumT rhs) noexcept { return (EnumT)((unsigned)lhs | (unsigned)rhs); } \
    constexpr EnumT operator&(EnumT lhs, EnumT rhs) noexcept { return (EnumT)((unsigned)lhs & (unsigned)rhs); } \
    constexpr EnumT operator^(EnumT lhs, EnumT rhs) noexcept { return (EnumT)((unsigned)lhs ^ (unsigned)rhs); }

//! Helper macro for constructor deduction guide and Mode flags operations.
#define UNICORN_HPP_IMPL_ARCH(ARCH)             \
    UNICORN_HPP_IMPL_FLAGS(ARCH::Mode);         \
    EngineOwner(ARCH::Mode)->EngineOwner<ARCH>; \
    EngineOwner(ARCH::Mode, char const*)->EngineOwner<ARCH>;

namespace uc::ffi {
/// This define prevents unicorn from including garbage
#define UNICORN_PLATFORM_H
#ifdef UNICORN_HAS_OSXKERNEL
#    undef UNICORN_HAS_OSXKERNEL
#endif
#include <unicorn/unicorn.h>
#if UC_API_MAJOR != 2
#    error "Unicorn API must be v2.x.y.z"
#endif
}

namespace uc::utility {
    //! @brief Helper function that returns either argument or nullptr depending on overload.
    constexpr void* arg_or_nullptr(void const* arg) noexcept { return const_cast<void*>(arg); }

    //! @brief Helper function that returns either argument or nullptr depending on overload.
    constexpr void* arg_or_nullptr() noexcept { return nullptr; }

    //! @brief Checks if two type have equal representation in memory.
    //!
    //! @todo Switch to std::is_layout_compatible for compilers that support it.
    template <typename TypeA, typename TypeB>
    constexpr bool is_layout_compatible_v = sizeof(TypeA) == sizeof(TypeB);
}

namespace uc::error {
#ifndef UNCIRON_HPP_DISABLE_LOCATION
    //! @brief Represents location in source code.
    using Location = std::source_location;
#else
    //! @brief Represents location in source code.
    //!
    //! @note this is stub of std::source_location.
    struct Location {
        //! @brief Return current source location.
        static constexpr Location current() noexcept { return {}; }

        //! @brief Return empty source location.
        constexpr Location() noexcept = default;

        //! @brief Line in source file.
        constexpr std::uint_least32_t line() const noexcept { return 0; }

        //! @brief Column in source file.
        constexpr std::uint_least32_t column() const noexcept { return 0; }

        //! @brief File name of source.
        constexpr const char* file_name() const noexcept { return ""; }

        //! @brief Function name in source.
        constexpr const char* function_name() const noexcept { return ""; }
    };
#endif

    //! @brief Error code enum.
    enum Error : unsigned {
        OK = ffi::UC_ERR_OK,                                ///< No error: everything was fine.
        ERR_NOMEM = ffi::UC_ERR_NOMEM,                      ///< Out-Of-Memory error.
        ERR_ARCH = ffi::UC_ERR_ARCH,                        ///< Unsupported architecture.
        ERR_HANDLE = ffi::UC_ERR_HANDLE,                    ///< Invalid handle.
        ERR_MODE = ffi::UC_ERR_MODE,                        ///< Invalid/unsupported mode.
        ERR_VERSION = ffi::UC_ERR_VERSION,                  ///< Unsupported version.
        ERR_READ_UNMAPPED = ffi::UC_ERR_READ_UNMAPPED,      ///< Quit emulation due to READ on unmapped memory.
        ERR_WRITE_UNMAPPED = ffi::UC_ERR_WRITE_UNMAPPED,    ///< Quit emulation due to WRITE on unmapped memory.
        ERR_FETCH_UNMAPPED = ffi::UC_ERR_FETCH_UNMAPPED,    ///< Quit emulation due to FETCH on unmapped memory.
        ERR_HOOK = ffi::UC_ERR_HOOK,                        ///< Invalid hook type.
        ERR_INSN_INVALID = ffi::UC_ERR_INSN_INVALID,        ///< Quit emulation due to invalid instruction.
        ERR_MAP = ffi::UC_ERR_MAP,                          ///< Invalid memory mapping.
        ERR_WRITE_PROT = ffi::UC_ERR_WRITE_PROT,            ///< Quit emulation due to UC_MEM_WRITE_PROT violation.
        ERR_READ_PROT = ffi::UC_ERR_READ_PROT,              ///< Quit emulation due to UC_MEM_READ_PROT violation.
        ERR_FETCH_PROT = ffi::UC_ERR_FETCH_PROT,            ///< Quit emulation due to UC_MEM_FETCH_PROT violation.
        ERR_ARG = ffi::UC_ERR_ARG,                          ///< Inavalid argument provided.
        ERR_READ_UNALIGNED = ffi::UC_ERR_READ_UNALIGNED,    ///< Unaligned read.
        ERR_WRITE_UNALIGNED = ffi::UC_ERR_WRITE_UNALIGNED,  ///< Unaligned write.
        ERR_FETCH_UNALIGNED = ffi::UC_ERR_FETCH_UNALIGNED,  ///< Unaligned fetch.
        ERR_HOOK_EXIST = ffi::UC_ERR_HOOK_EXIST,            ///< Hook for this event already existed.
        ERR_RESOURCE = ffi::UC_ERR_RESOURCE,                ///< Insufficient resource.
        ERR_EXCEPTION = ffi::UC_ERR_EXCEPTION,              ///< Unhandled CPU exception.
    };

    //! @brief Empty type.
    struct None {};

    //! @brief Exception type thrown from a call to .expect() or a throwing constructor.
    struct Exception : std::exception {
        //! @brief Error code or Error::OK.
        Error error = {};

        //! @brief Reason for checking error.
        char const* why = "";

        //! @brief Location of call to .expect().
        //!
        //! @note This is stubed in non-debug builds.
        [[no_unique_address]] Location where = {};

        //! @brief Constructs new exception from Error code and source Location.
        //!
        //! @param error code that was signaled.
        //! @param why this operation was expected not to fail.
        //! @param where is the location of error check.
        Exception(Error error, char const* why, Location where) noexcept : error(error), why(why), where(where) {}

        //! @brief Returns description of error code.
        char const* what() const noexcept final { return ffi::uc_strerror((ffi::uc_err)error); }

        //! @brief Check if exception is equal to error.
        bool operator==(Error rhs) const noexcept { return error == rhs; }

        //! @brief Check if exception is not equal to error.
        bool operator!=(Error rhs) const noexcept { return !operator==(rhs); }

        //! @brief Print error in nice format.
        //!
        //! @param out FILE to print in.
        void print(FILE* out = stderr) const noexcept {
            fprintf(out, "%s[%s]@%s:%s:%d\n", what(), why, where.file_name(), where.function_name(), where.line());
        }
    };

    //! @brief Type containing Error + Value.
    //!
    //! @note Value should allways be in valid state even if result contains an error.
    template <typename T = None>
    struct [[nodiscard]] Result {
        //! @brief Contains error code or Error:OK.
        Error error = {};

        //! @brief Contains value.
        [[no_unique_address]] T value = {};

        //! @brief Returs value as mutable reference or throws an Exception.
        //!
        //! @param why this operation was expected not to fail.
        //! @param where is the location of error check.
        T& expect(char const* why = "", Location where = Location::current()) & noexcept(false) {
            if (error != Error::OK) {
                throw Exception{error, why, where};
            }
            return value;
        }

        //! @brief Returns value as immutable refrence or throws an Exception.
        //!
        //! @param why this operation was expected not to fail.
        //! @param where is the location of error check.
        T const& expect(char const* why = "", Location where = Location::current()) const& noexcept(false) {
            if (error != Error::OK) {
                throw Exception{error, why, where};
            }
            return value;
        }

        //! @brief Returns value and consumes current Result or throws an Exception.
        //!
        //! @param why this operation was expected not to fail.
        //! @param where is the location of error check.
        T&& expect(char const* why = "", Location where = Location::current()) && noexcept(false) {
            if (error != Error::OK) {
                throw Exception{error, why, where};
            }
            return static_cast<T&&>(value);
        }

        //! @brief Check out the value and return the error.
        //!
        //! @param[out] out variable reference to check value into.
        template <typename O>
        Error check_out(O& out) const& noexcept {
            out = static_cast<T const&>(value);
            return error;
        }

        //! @brief Check out the value and return the error.
        //!
        //! @param[out] out variable reference to check value into.
        template <typename O>
        Error check_out(O& out) && noexcept {
            out = static_cast<T&&>(value);
            return error;
        }

        //! @brief Returns underlying value as a mutable reference.
        T& operator*() & noexcept { return value; }

        //! @brief Returns underlying value as a immutable reference.
        T const& operator*() const& noexcept { return value; }

        //! @brief Return underlying value and consumes current Result or throws an Exception.
        T&& operator*() && noexcept { return static_cast<T&&>(value); }

        //! @brief Access underlying value as mutable reference.
        T* operator->() noexcept { return &value; }

        //! @brief Access underlying value as immutable reference.
        T const* operator->() const noexcept { return &value; }

        //! @brief Returns true if there is no error.
        explicit operator bool() const noexcept { return error == Error::OK; }

        //! @brief Returns true if there is error.
        bool operator!() const noexcept { return error != Error::OK; }

        //! @brief Check if result equal to error.
        bool operator==(Error rhs) const noexcept { return error == rhs; }

        //! @brief Check if result is not equal to error.
        bool operator!=(Error rhs) const noexcept { return !operator==(rhs); }

        //! @brief Converts Result<T> into Result<O> by copying the underyling value.
        template <typename O>
        Result<O> into() const& noexcept {
            return {error, static_cast<O>(value)};
        }

        //! @brief Converts Result<T> into Result<O> by moving the underlying value.
        template <typename O>
        Result<O> into() && noexcept {
            return {error, static_cast<O>(static_cast<T&&>(value))};
        }
    };
}

namespace uc::mem {
    using error::Error;
    using error::Exception;
    using error::Location;
    using error::Result;

    //! @brief 64bit value represented as 2 32bit values.
    using U64 = std::array<std::uint32_t, 2>;

    //! @brief 128bit value split into multiple 64bit values.
    using U128 = std::array<std::uint64_t, 2>;

    //! @brief 256bit value split into multiple 64bit values.
    using U256 = std::array<std::uint64_t, 4>;

    //! @brief 512bit value split into multiple 64bit values.
    using U512 = std::array<std::uint64_t, 8>;

    //! @brief Type of maxium storage for memory address.
    using Address = std::uint64_t;

    //! @brief Type of maximum storage for memory read/writes.
    using Value = std::uint64_t;

    //! @brief Type of memory access, used in memory hook callback.
    enum Access : unsigned {
        ACCESS_READ = ffi::UC_MEM_READ,                      ///< Memory is read from.
        ACCESS_WRITE = ffi::UC_MEM_WRITE,                    ///< Memory is written to.
        ACCESS_FETCH = ffi::UC_MEM_FETCH,                    ///< Memory is fetched.
        ACCESS_READ_UNMAPPED = ffi::UC_MEM_READ_UNMAPPED,    ///< Unmapped memory is read from.
        ACCESS_WRITE_UNMAPPED = ffi::UC_MEM_WRITE_UNMAPPED,  ///< Unmapped memory is written t.
        ACCESS_FETCH_UNMAPPED = ffi::UC_MEM_FETCH_UNMAPPED,  ///< Unmapped memory is fetche.
        ACCESS_WRITE_PROT = ffi::UC_MEM_WRITE_PROT,          ///< Write to write protected, but mapped, memory.
        ACCESS_READ_PROT = ffi::UC_MEM_READ_PROT,            ///< Read from read protected, but mapped, memory.
        ACCESS_FETCH_PROT = ffi::UC_MEM_FETCH_PROT,          ///< Fetch from non-executable, but mapped, memory.
        ACCESS_READ_AFTER = ffi::UC_MEM_READ_AFTER,          ///< Memory is read from (successful access).
    };

    //! @brief Protection bitflags on memory region.
    enum Prot : unsigned {
        PROT_NONE = ffi::UC_PROT_NONE,    ///< This memory is unaccessible.
        PROT_READ = ffi::UC_PROT_READ,    ///< This memory is readable.
        PROT_WRITE = ffi::UC_PROT_WRITE,  ///< This memory is writable.
        PROT_EXEC = ffi::UC_PROT_EXEC,    ///< This memory is executable.
        PROT_ALL = ffi::UC_PROT_ALL,      ///< This memory is readable, writeable and executable.
    };
    UNICORN_HPP_IMPL_FLAGS(Prot);

    //! @brief Bitflags used in creation of memory hook.
    enum Hook : unsigned {
        // clang-format off
        HOOK_READ_UNMAPPED = ffi::UC_HOOK_MEM_READ_UNMAPPED,                             ///< Hook for memory read on unmapped memory.
        HOOK_WRITE_UNMAPPED = ffi::UC_HOOK_MEM_WRITE_UNMAPPED,                           ///< Hook for invalid memory write event.
        HOOK_FETCH_UNMAPPED = ffi::UC_HOOK_MEM_FETCH_UNMAPPED,                           ///< Hook for invalid memory fetch for execution event.
        HOOK_READ_PROT = ffi::UC_HOOK_MEM_READ_PROT,                                     ///< Hook for memory read on read-protected memory.
        HOOK_WRITE_PROT = ffi::UC_HOOK_MEM_WRITE_PROT,                                   ///< Hook for memory write on write-protected memory.
        HOOK_FETCH_PROT = ffi::UC_HOOK_MEM_FETCH_PROT,                                   ///< Hook for memory fetch on non-executable memory.
        HOOK_READ = ffi::UC_HOOK_MEM_READ,                                               ///< Hook memory read events.
        HOOK_WRITE = ffi::UC_HOOK_MEM_WRITE,                                             ///< Hook memory write events.
        HOOK_FETCH = ffi::UC_HOOK_MEM_FETCH,                                             ///< Hook memory fetch for execution event.
        HOOK_READ_AFTER = ffi::UC_HOOK_MEM_READ_AFTER,                                   ///< Hook memory read events, but only successful access.
        HOOK_UNMAPPED = HOOK_READ_UNMAPPED + HOOK_WRITE_UNMAPPED + HOOK_FETCH_UNMAPPED,  ///< Hook type for all events of unmapped memory access.
        HOOK_PROT = HOOK_READ_PROT + HOOK_WRITE_PROT + HOOK_FETCH_PROT,                  ///< Hook type for all events of illegal protected memory access.
        HOOK_READ_INVALID = HOOK_READ_PROT + HOOK_READ_UNMAPPED,                         ///< Hook type for all events of illegal read memory access.
        HOOK_WRITE_INVALID = HOOK_WRITE_PROT + HOOK_WRITE_UNMAPPED,                      ///< Hook type for all events of illegal write memory access.
        HOOK_FETCH_INVALID = HOOK_FETCH_PROT + HOOK_FETCH_UNMAPPED,                      ///< Hook type for all events of illegal fetch memory access.
        HOOK_INVALID = HOOK_UNMAPPED + HOOK_PROT,                                        ///< Hook type for all events of illegal memory access.
        HOOK_VALID = HOOK_READ + HOOK_WRITE + HOOK_FETCH,                                ///< Hook type for all events of valid memory access.
        HOOK_ALL = HOOK_INVALID + HOOK_VALID,                                            ///< Hook all types of memory access.
        // clang-format on
    };
    UNICORN_HPP_IMPL_FLAGS(Hook);

    //! @brief Represent range(inclusive) in memory.
    struct Range {
        //! @brief First address in memory range.
        Address first;

        //! @brief Last(inclusive) address in memory range.
        Address last;

        //! @brief Constructs invalid memory range.
        constexpr Range() noexcept : first(1), last(0) {}

        //! @brief Constructs memory range of single address.
        //!
        //! @param index of address
        constexpr Range(Address index) noexcept : first(index), last(index) {}

        //! @brief Constructs memory range [first, last].
        //!
        //! @param first address(inclusive)
        //! @param last address(inclusive)
        constexpr Range(Address first, Address last) noexcept : first(first), last(last) {}

        //! @brief Count of bytes in range.
        constexpr std::size_t size() const noexcept { return (last - first) + 1; }

        //! @brief Checks if range is valid.
        constexpr bool valid() const noexcept { return last >= first; }

        //! @brief Check if two ranges are equal.
        //!
        //! @note If both ranges are invalid they compare as equal.
        constexpr bool operator==(Range const& rhs) const noexcept {
            if (!valid() && !rhs.valid()) return true;
            return first == rhs.first && last == rhs.last;
        }

        //! @brief Check if two ranges are not equal.
        constexpr bool operator!=(Range const& rhs) const noexcept { return !operator==(rhs); }
    };

    //! @brief Single region(Range + Prot) of memory.
    struct Region {
        //! @brief Range(inclusive) of this memory region.
        Range range;

        //! @brief Protection flags of this memory region.
        Prot prot;

        //! @brief Count of bytes in memory region.
        constexpr std::size_t size() const noexcept { return range.size(); }
    };
    static_assert(utility::is_layout_compatible_v<Region, ffi::uc_mem_region>);

    //! @brief Owned list of memory Region.
    struct RegionVector {
        //! @brief Default-constructible as empty list of Region.
        RegionVector() noexcept = default;

        //! @brief Can not be copyied.
        RegionVector(RegionVector const&) = delete;

        //! @brief Can be move-constructed.
        RegionVector(RegionVector&& other) noexcept
            : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)) {}

        //! @brief Construct RegionVector from pointer + size.
        //!
        //! @remarks RegionVector takes ownership of pointer.
        RegionVector(Region* data, std::size_t size) noexcept : data_(data), size_(size) {}

        //! @brief Can be move-constructed from another instanc.
        RegionVector& operator=(RegionVector other) {
            std::swap(data_, other.data_);
            std::swap(size_, other.size_);
            return *this;
        }

        //! @brief Has to free free owned memory.
        ~RegionVector() noexcept { (void)this->clear(); }

        //! @brief Start of mutable iterator over memory Region.
        Region* begin() & noexcept { return data_; }

        //! @brief End of mutable iterator over memory Region.
        Region* end() & { return data_ + size_; }

        //! @brief Start of implicitly immutable iterator over memory Region.
        Region const* begin() const& noexcept { return data_; }

        //! @brief End of implicitly immutable iterator over memory Region.
        Region const* end() const& { return data_ + size_; }

        //! @brief Start of explicitly immutable iterator over memory Region.
        Region const* cbegin() const& { return data_; }

        //! @brief End of explicitly immutable iterator over memory Region.
        Region const* cend() const& { return data_ + size_; }

        //! @brief Mutable pointer to first regio.
        Region* data() & noexcept { return data_; }

        //! @brief Immutable pointer to first regio.
        Region const* data() const& noexcept { return data_; }

        //! @brief Count of region.
        std::size_t size() const noexcept { return size_; }

        //! @brief Clear all data if any.
        Result<> clear() noexcept {
            if (std::exchange(size_, std::size_t{0})) {
                if (auto const ptr = std::exchange(data_, nullptr)) {
                    auto const error = ffi::uc_free(ptr);
                    return {(Error)error};
                }
            }
            return {Error::OK};
        }

    private:
        Region* data_ = {};
        std::size_t size_ = {};
    };

    //! @brief API for single register.
    //!
    //! @note Any access that fails to be read will be 0 initialized
    //! @note Any access that fails to write will be silently ignored
    //!
    //! @tparam T storage type of maximum size for this register
    //! @tparam ID for this register
    template <typename T, auto ID>
    struct Register {
        //! @brief Internal handle to unicorn engine.
        ffi::uc_engine* _uc;

        //! @brief Read register.
        T read() const noexcept {
            T value = {};
            ffi::uc_reg_read(_uc, ID, &value);
            return value;
        }

        //! @brief Write register value.
        //!
        //! @param value to write from
        void write(T const& value) const noexcept { ffi::uc_reg_write(_uc, ID, &value); }

        //! @brief Read register as if it were bitcasted into type IntoT.
        //!
        //! @note If IntoT is smaller than T, extra bytes are discarded.
        //!
        //! @tparam IntoT type to read as.
        template <typename IntoT>
        IntoT read_bitcast() const noexcept {
            static_assert(std::is_trivially_copyable_v<IntoT> && sizeof(IntoT) <= sizeof(T));

            char buffer[sizeof(T)] = {};
            ffi::uc_reg_read(_uc, ID, buffer);

            IntoT value = {};
            std::memcpy(&value, buffer, sizeof(IntoT));

            return value;
        }

        //! @brief Write register as if it were bitcasted from type FromT.
        //!
        //! @note If FromT is smaller than T, extra bytes are zeroed.
        //!
        //! @param value to write from.
        //! @tparam FromT type to read as.
        template <typename FromT>
        void write_bitcast(FromT const& value) const noexcept {
            static_assert(std::is_trivially_copyable_v<FromT> && sizeof(FromT) <= sizeof(T));

            char buffer[sizeof(T)] = {};
            std::memcpy(buffer, &value, sizeof(FromT));

            ffi::uc_reg_write(_uc, ID, buffer);
        }

        //! @brief Register reference type return by operator*
        struct Ref {
            //! @brief Internal handle to unicorn engine.
            ffi::uc_engine* const _uc;

            //! @brief Automatically converts to underlying type.
            operator T() const noexcept {
                T value = {};
                ffi::uc_reg_read(_uc, ID, &value);
                return value;
            }

            //! @brief Can be assigned from anything that converts into T.
            //!
            //! @param value to write
            T operator=(T const& value) const noexcept {
                ffi::uc_reg_write(_uc, ID, &value);
                return value;
            }

            //! @brief Assign register to itself is meaningles.
            void operator=(Ref&& value) = delete;
        };

        //! @brief Access register from operator*.
        Ref operator*() const noexcept { return Ref{_uc}; }
    };
}

namespace uc::tcg {
    using error::Error;
    using error::Exception;
    using error::Location;
    using error::Result;

    //! @brief Represent a TranslationBlock.
    struct TB {
        //! @brief Address of translation block.
        mem::Address pc;

        //! @brief Count of instructions in address block.
        std::uint16_t icount;

        //! @brief Size of translation block.
        std::uint16_t size;

        //! @brief Check if two TB are equal.
        constexpr bool operator==(TB const& rhs) const noexcept {
            return std::tie(pc, icount, size) == std::tie(rhs.pc, rhs.icount, rhs.size);
        }

        //! @brief Check if two TB are not equal.
        constexpr bool operator!=(TB const& rhs) const noexcept { return !operator==(rhs); }
    };
    static_assert(utility::is_layout_compatible_v<TB, ffi::uc_tb>);
}

namespace uc {
    using error::Error;
    using error::Exception;
    using error::Location;
    using error::Result;

    //! @brief Unmaanged ID for a hook instance.
    enum class HookID : std::size_t {};

    //! @brief Managed handle for a hook instance.
    //!
    //! @note When handle exists the scope, hook is automatically destroyed.
    struct Hook {
        //! @brief Construct empty Hook manager.
        Hook() = default;

        //! @brief Construct hook from hook id
        Hook(HookID id, ffi::uc_engine* uc) noexcept : id_(id), uc_(uc) {}

        //! @brief Move constructs hook handle.
        Hook(Hook&& other) noexcept : id_(std::exchange(other.id_, HookID{})), uc_(std::exchange(other.uc_, nullptr)) {}

        //! @brief Hook handles can't be copied(they are unique), only std::move-ed.
        Hook(Hook const&) = delete;

        //! @brief Move assigns hook handle.
        Hook& operator=(Hook other) noexcept {
            std::swap(other.id_, id_);
            std::swap(other.uc_, uc_);
            return *this;
        }

        //! @brief Destroys non-null hook.
        ~Hook() noexcept {
            auto const id = std::exchange(id_, HookID{});
            auto const uc = std::exchange(uc_, nullptr);
            if (id != HookID{} && uc) {
                ffi::uc_hook_del(uc, (ffi::uc_hook)id);
            }
        }

        //! @brief Checks if Hook is valid (not null).
        explicit operator bool() const noexcept { return id_ != HookID{} && uc_; }

        //! @brief Checks if Hook is not valid(null).
        bool operator!() const noexcept { return id_ == HookID{} || uc_; }

        //! @brief Converts managed Hook into unmanaged HookID.
        //!
        //! @note This will make original Hook object null.
        explicit operator HookID() && noexcept {
            auto const id = std::exchange(id_, HookID{});
            auto const uc = std::exchange(uc_, nullptr);
            return id;
        }

    private:
        //! @brief Unique id of hook instance.
        HookID id_ = {};

        //! @brief Raw pointer to engine this hook belongs to.
        ffi::uc_engine* uc_ = {};
    };

    //! @brief Unowned handle for unicorn engine instance.
    //!
    //! @tparam Arch type of engine architecture.
    template <typename Arch>
    struct EngineHandle {
        //! @brief Architecture specific CPU model.
        using CPU = typename Arch::CPU;

        //! @brief Architecture specific CPU mode of execution.
        using Mode = typename Arch::Mode;

        //! @brief API for unicorn engine registers.
        using RegsAPI = typename Arch::RegsAPI;

        //! @brief API for control operations.
        union CtlAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            //! @brief Get current mode.
            Result<Mode> get_mode() const noexcept {
                using namespace ffi;
                auto mode = Mode{};
                auto const error = uc_ctl_get_mode(_uc, &mode);
                return {(Error)error, mode};
            }

            //! @brief Get current page size.
            Result<std::size_t> get_page_size() const noexcept {
                using namespace ffi;
                auto page_size = std::uint32_t{};
                auto const error = uc_ctl_get_page_size(_uc, &page_size);
                return {(Error)error, page_size};
            }

            //! @brief Set current page size.
            Result<> set_page_size(std::size_t page_size) const noexcept {
                using namespace ffi;
                auto const error = uc_ctl_set_page_size(_uc, (std::uint32_t)page_size);
                return {(Error)error};
            }

            //! @brief Get current timeout.
            Result<std::chrono::microseconds> get_timeout() const noexcept {
                using namespace ffi;
                auto timeout = std::int64_t{};
                auto const error = uc_ctl_get_timeout(_uc, &timeout);
                return {(Error)error, std::chrono::microseconds(timeout)};
            }

            //! @brief Enable multiple exits.
            Result<> exits_enable() const noexcept {
                using namespace ffi;
                auto const error = uc_ctl_exits_enable(_uc);
                return {(Error)error};
            }

            //! @brief Disable multiple exits.
            Result<> exits_disable() const noexcept {
                using namespace ffi;
                auto const error = uc_ctl_exits_disable(_uc);
                return {(Error)error};
            }

            //! @brief Get number of current exits.
            Result<std::size_t> get_exits_cnt() const noexcept {
                using namespace ffi;
                auto count = std::size_t{};
                auto const error = uc_ctl_get_exits_cnt(_uc, &count);
                return {(Error)error, count};
            }

            //! @brief Read current exits into buffer.
            Result<> get_exits(mem::Address* buffer, std::size_t len) const noexcept {
                using namespace ffi;
                auto const error = uc_ctl_get_exits(_uc, buffer, len);
                return {(Error)error};
            }

            //! @brief Write current exits from buffer.
            Result<> set_exits(mem::Address const* buffer, std::size_t len) const noexcept {
                using namespace ffi;
                auto const error = uc_ctl_get_exits(_uc, buffer, len);
                return {(Error)error};
            }

            //! @brief Get CPU model of unicorn engine instance.
            Result<CPU> get_cpu_model() const noexcept {
                using namespace ffi;
                auto model = CPU{Arch::CPU_DEFAULT};
                auto const error = uc_ctl_get_cpu_model(_uc, &model);
                return {(Error)error, model};
            }

            //! @brief Set CPU model of unicorn engine instance.
            //!
            //! @remarks This can only be called once immediately after engine instance is created.
            Result<> set_cpu_model(CPU model) const noexcept {
                using namespace ffi;
                auto const error = uc_ctl_set_cpu_model(_uc, model);
                return {(Error)error};
            }

            //! @brief Invalidate a tb cache at a specific range.
            //!
            //! @param range of tb cache.
            Result<> remove_cache(mem::Range range) const noexcept {
                using namespace ffi;
                auto const error = uc_ctl_remove_cache(_uc, range.first, range.last);
                return {(Error)error};
            }

            //! @brief Request a tb cache at a specific address.
            //!
            //! @param address of tb cache.
            Result<tcg::TB> request_cache(mem::Address address) const noexcept {
                using namespace ffi;
                auto tb = tcg::TB{};
                auto const error = uc_ctl_request_cache(_uc, address, &tb);
                return {(Error)error, tb};
            }
        };

        //! @brief API for query operations.
        union QueryAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            //! @brief Current mode of CPU.
            Result<Mode> mode() const noexcept {
                using namespace ffi;
                auto value = std::size_t{};
                auto const error = ffi::uc_query(_uc, ffi::UC_QUERY_MODE, &value);
                return {(Error)error, (Mode)value};
            }

            //! @brief Page size of engine.
            Result<std::size_t> page_size() const noexcept {
                using namespace ffi;
                auto value = std::size_t{};
                auto const error = ffi::uc_query(_uc, ffi::UC_QUERY_PAGE_SIZE, &value);
                return {(Error)error, value};
            }

            //! @brief If emulation stops due to timeout.
            Result<bool> timeout() const noexcept {
                using namespace ffi;
                auto value = std::size_t{};
                auto const error = ffi::uc_query(_uc, ffi::UC_QUERY_TIMEOUT, &value);
                return {(Error)error, (bool)value};
            }
        };

        //! @brief API for emulation operations.
        union EmuAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            //! @brief Start emulation
            //!
            //! @param begin address of execution
            //! @param end address of execution
            //! @param duration to execute
            //! @param count of instructions to execute
            Result<> start(mem::Address begin,
                           mem::Address end,
                           std::chrono::microseconds duration = {},
                           std::size_t count = 0) const noexcept {
                auto const error = ffi::uc_emu_start(_uc, begin, end, duration.count(), count);
                return {(Error)error};
            }

            //! @brief Stop emulation
            Result<> stop() const noexcept {
                auto const error = ffi::uc_emu_stop(_uc);
                return {(Error)error};
            }
        };

        //! @brief API for unciron engine memory.
        union MemAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            //! @brief Read memory into raw pointer.
            //!
            //! @param address of memory to read from
            //! @param dst pointer to read into
            //! @param size of data in bytes
            Result<> read(mem::Address address, void* dst, std::size_t size) const noexcept {
                auto const error = ffi::uc_mem_read(_uc, address, dst, size);
                return {(Error)error};
            }

            //! @brief Write memory from raw pointer.
            //!
            //! @param address of memory to write into
            //! @param src pointer to read from
            //! @param size of data in bytes
            Result<> write(mem::Address address, void const* src, std::size_t size) const noexcept {
                auto const error = ffi::uc_mem_write(_uc, address, src, size);
                return {(Error)error};
            }

            //! @brief Read from memory as if it contains value of type IntoT.
            //!
            //! @tparam IntoT type to read as
            //! @param address of memory to read from
            template <typename IntoT>
            Result<IntoT> read_bitcast(mem::Address address) const noexcept {
                static_assert(std::is_trivially_copyable_v<IntoT>);
                auto value = IntoT{};
                auto const error = ffi::uc_mem_read(_uc, address, &value, sizeof(IntoT));
                return {(Error)error, value};
            }

            //! @brief Write to memory as if it contains value of type FromT.
            //!
            //! @tparam FromT type to write as
            //! @param address of memory to write to
            //! @param value of type IntoT to write from
            template <typename FromT>
            Result<> write_bitcast(mem::Address address, FromT const& value) const noexcept {
                static_assert(std::is_trivially_copyable_v<FromT>);
                auto const error = ffi::uc_mem_write(_uc, address, &value, sizeof(FromT));
                return {(Error)error};
            }

            //! @brief Map region of memory.
            //!
            //! @param address of memory to map
            //! @param size of memory to map
            //! @param prot flags to apply to memory
            Result<> map(mem::Address address, std::size_t size, mem::Prot prot) const noexcept {
                auto const error = ffi::uc_mem_map(_uc, address, size, prot);
                return {(Error)error};
            }

            //! @brief Map raw pointer to region of memory.
            //!
            //! @param address of memory to map
            //! @param size of memory to map
            //! @param prot flags to apply to memory
            //! @param ptr pointer to use for memory backing
            Result<> map_ptr(mem::Address address, std::size_t size, mem::Prot prot, void* ptr) const noexcept {
                auto const error = ffi::uc_mem_map_ptr(_uc, address, size, prot, ptr);
                return {(Error)error};
            }

            //! @brief Unmap region of memory.
            //!
            //! @param address of memory to map
            //! @param size of memory to map
            Result<> unmap(mem::Address address, std::size_t size) const noexcept {
                auto const error = ffi::uc_mem_unmap(_uc, address, size);
                return {(Error)error};
            }

            //! @brief Change protection flags on region of memory.
            //!
            //! @param address of memory
            //! @param size of memory
            //! @param prot flags
            Result<> protect(mem::Address address, std::size_t size, mem::Prot prot) const noexcept {
                auto const error = ffi::uc_mem_protect(_uc, address, size, prot);
                return {(Error)error};
            }

            //! @brief Query list of memory regions
            Result<mem::RegionVector> regions() const noexcept {
                ffi::uc_mem_region* data = {};
                auto size = std::uint32_t{};
                auto const error = ffi::uc_mem_regions(_uc, &data, &size);
                return {(Error)error, {(mem::Region*)data, size}};
            }

            //! @brief Hook memory mapped input/output read-write.
            //!
            //! @note size should be aligned to page size
            //!
            //! @tparam function_read to invoke on read
            //! @tparam function_write to invoke on write
            //! @tparam optional ObjectT type to pass to function
            //! @param address of memory region
            //! @param size of memory region
            //! @param object pointer to pass to functions as first argument
            template <auto function_read, auto function_write, typename... ObjectT>
            Result<> map_mmio_rw(mem::Address address, std::size_t size, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_mmio_read_t trampoline_read =
                    [](ffi::uc_engine* uc, std::uint64_t offset, unsigned size, void* user_data) -> std::uint64_t {
                    return std::invoke(function_read,
                                       reinterpret_cast<ObjectT*>(user_data)...,
                                       static_cast<EngineHandle>(uc),
                                       static_cast<mem::Address>(offset),
                                       static_cast<std::size_t>(size));
                };
                constexpr ffi::uc_cb_mmio_write_t trampoline_write = [](ffi::uc_engine* uc,
                                                                        std::uint64_t offset,
                                                                        unsigned size,
                                                                        std::uint64_t value,
                                                                        void* user_data) -> void {
                    return std::invoke(function_write,
                                       reinterpret_cast<ObjectT*>(user_data)...,
                                       static_cast<EngineHandle>(uc),
                                       static_cast<mem::Address>(offset),
                                       static_cast<std::size_t>(size),
                                       static_cast<mem::Value>(value));
                };
                auto const error = ffi::uc_mmio_map(_uc,
                                                    address,
                                                    size,
                                                    trampoline_read,
                                                    utility::arg_or_nullptr(object...),
                                                    trampoline_write,
                                                    utility::arg_or_nullptr(object...));
                return {(Error)error};
            }

            //! @brief Hook memory mapped input/output read only.
            //!
            //! @note size should be aligned to page size
            //!
            //! @tparam function_read to invoke on read
            //! @tparam optional ObjectT type to pass to function
            //! @param address of memory region
            //! @param size of memory region
            //! @param object pointer to pass to functions as first argument
            template <auto function_read, typename... ObjectT>
            Result<> map_mmio_ro(mem::Address address, std::size_t size, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_mmio_read_t trampoline_read =
                    [](ffi::uc_engine* uc, std::uint64_t offset, unsigned size, void* user_data) -> std::uint64_t {
                    return std::invoke(function_read,
                                       reinterpret_cast<ObjectT*>(user_data)...,
                                       static_cast<EngineHandle>(uc),
                                       static_cast<mem::Address>(offset),
                                       static_cast<std::size_t>(size));
                };
                auto const error = ffi::uc_mmio_map(
                    _uc, address, size, trampoline_read, utility::arg_or_nullptr(object...), nullptr, nullptr);
                return {(Error)error};
            }

            //! @brief Hook memory mapped input/output write-only.
            //!
            //! @note size should be aligned to page size
            //!
            //! @tparam function_write to invoke on write
            //! @tparam optional ObjectT type to pass to function
            //! @param address of memory region
            //! @param size of memory region
            //! @param object pointer to pass to functions as first argument
            template <auto function_write, typename... ObjectT>
            Result<> map_mmio_wo(mem::Address address, std::size_t size, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_mmio_write_t trampoline_write = [](ffi::uc_engine* uc,
                                                                        std::uint64_t offset,
                                                                        unsigned size,
                                                                        std::uint64_t value,
                                                                        void* user_data) -> void {
                    return std::invoke(function_write,
                                       reinterpret_cast<ObjectT*>(user_data)...,
                                       static_cast<EngineHandle>(uc),
                                       static_cast<mem::Address>(offset),
                                       static_cast<std::size_t>(size),
                                       static_cast<mem::Value>(value));
                };
                auto const error = ffi::uc_mmio_map(
                    _uc, address, size, nullptr, nullptr, trampoline_write, utility::arg_or_nullptr(object...));
                return {(Error)error};
            }
        };

        //! @brief API for unicorn engine hooks.
        union HookAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            //! @brief Hook memory access of type.
            //!
            //! @details Callback can map memory and return true on invalid access to recevor.
            //!
            //! @tparam function to invoke on callback
            //! @tparam optional ObjectT type to pass to function
            //! @param range of memory to hook in
            //! @param type of memory access to hook
            //! @param object pointer to pass to function as first argument
            template <auto function, typename... ObjectT>
            Result<Hook> add_mem(mem::Range range, mem::Hook type, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_eventmem_t trampoline = [](ffi::uc_engine* uc,
                                                                ffi::uc_mem_type type,
                                                                std::uint64_t address,
                                                                int size,
                                                                std::int64_t value,
                                                                void* user_data) -> bool {
                    return std::invoke(function,
                                       reinterpret_cast<ObjectT*>(user_data)...,
                                       static_cast<EngineHandle>(uc),
                                       static_cast<mem::Access>(type),
                                       static_cast<mem::Address>(address),
                                       static_cast<std::size_t>(size),
                                       static_cast<mem::Value>(value));
                };
                auto id = HookID{};
                auto const error = ffi::uc_hook_add(_uc,
                                                    reinterpret_cast<ffi::uc_hook*>(&id),
                                                    static_cast<ffi::uc_hook_type>(type),
                                                    reinterpret_cast<void*>(trampoline),
                                                    utility::arg_or_nullptr(object...),
                                                    range.first,
                                                    range.last);
                return {(Error)error, {id, _uc}};
            }

            //! @brief Hook on new edge generation. Could be useful in program analysis.
            //!
            //! @note The hook is called before executing code.
            //! @note The hook is only called when generation is triggered.
            //!
            //! @tparam function to invoke on callback
            //! @tparam optional ObjectT type to pass to function
            //! @param range of memory to hook in
            //! @param object pointer to pass to function as first argument
            template <auto function, typename... ObjectT>
            Result<Hook> add_edge_generated(mem::Range range, ObjectT*... object) const noexcept {
                constexpr ffi::uc_hook_edge_gen_t trampoline =
                    [](ffi::uc_engine* uc, tcg::TB const* cur_tb, tcg::TB const* prev_tb, void* user_data) -> bool {
                    return std::invoke(function,
                                       reinterpret_cast<ObjectT*>(user_data)...,
                                       static_cast<EngineHandle>(uc),
                                       *cur_tb,
                                       *prev_tb);
                };
                auto id = HookID{};
                auto const error = ffi::uc_hook_add(_uc,
                                                    reinterpret_cast<ffi::uc_hook*>(&id),
                                                    ffi::UC_HOOK_EDGE_GENERATED,
                                                    reinterpret_cast<void*>(trampoline),
                                                    utility::arg_or_nullptr(object...),
                                                    range.first,
                                                    range.last);
                return {(Error)error, {id, _uc}};
            }

            //! @brief Hook instructions.
            //!
            //! @tparam function to invoke on callback
            //! @tparam optional ObjectT type to pass to function
            //! @param range of memory to hook in
            //! @param object pointer to pass to function as first argument
            template <auto function, typename... ObjectT>
            Result<Hook> add_code(mem::Range range, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_hookcode_t trampoline =
                    [](ffi::uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data) -> void {
                    return std::invoke(function,
                                       reinterpret_cast<ObjectT*>(user_data)...,
                                       static_cast<EngineHandle>(uc),
                                       static_cast<mem::Address>(address),
                                       static_cast<std::size_t>(size));
                };
                auto id = HookID{};
                auto const error = ffi::uc_hook_add(_uc,
                                                    reinterpret_cast<ffi::uc_hook*>(&id),
                                                    ffi::UC_HOOK_CODE,
                                                    reinterpret_cast<void*>(trampoline),
                                                    utility::arg_or_nullptr(object...),
                                                    range.first,
                                                    range.last);
                return {(Error)error, {id, _uc}};
            }

            //! @brief Hook instruction blocks.
            //!
            //! @tparam function to invoke on callback
            //! @tparam optional ObjectT type to pass to function
            //! @param range of memory to hook in
            //! @param object pointer to pass to function as first argument
            template <auto function, typename... ObjectT>
            Result<Hook> add_block(mem::Range range, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_hookcode_t trampoline =
                    [](ffi::uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data) -> void {
                    return std::invoke(function,
                                       reinterpret_cast<ObjectT*>(user_data)...,
                                       static_cast<EngineHandle>(uc),
                                       static_cast<mem::Address>(address),
                                       static_cast<std::size_t>(size));
                };
                auto id = HookID{};
                auto const error = ffi::uc_hook_add(_uc,
                                                    reinterpret_cast<ffi::uc_hook*>(&id),
                                                    ffi::UC_HOOK_BLOCK,
                                                    reinterpret_cast<void*>(trampoline),
                                                    utility::arg_or_nullptr(object...),
                                                    range.first,
                                                    range.last);
                return {(Error)error, {id, _uc}};
            }

            //! @brief Hook interupt instruction.
            //!
            //! @tparam function to invoke on callback
            //! @tparam optional ObjectT type to pass to function
            //! @param range of memory to hook in
            //! @param object pointer to pass to function as first argument
            template <auto function, typename... ObjectT>
            Result<Hook> add_interupt(mem::Range range, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_hookintr_t trampoline =
                    [](ffi::uc_engine* uc, std::uint32_t number, void* user_data) -> void {
                    return std::invoke(
                        function, reinterpret_cast<ObjectT*>(user_data)..., static_cast<EngineHandle>(uc), number);
                };
                auto id = HookID{};
                auto const error = ffi::uc_hook_add(_uc,
                                                    reinterpret_cast<ffi::uc_hook*>(&id),
                                                    ffi::UC_HOOK_INTR,
                                                    reinterpret_cast<void*>(trampoline),
                                                    utility::arg_or_nullptr(object...),
                                                    range.first,
                                                    range.last);
                return {(Error)error, {id, _uc}};
            }

            //! @brief Hook invalid instructions.
            //!
            //! @tparam function to invoke on callback
            //! @tparam optional ObjectT type to pass to function
            //! @param range of memory to hook in
            //! @param object pointer to pass to function as first argument
            template <auto function, typename... ObjectT>
            Result<Hook> add_insn_invalid(mem::Range range, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_hookinsn_invalid_t trampoline = [](ffi::uc_engine* uc, void* user_data) -> bool {
                    return std::invoke(
                        function, (reinterpret_cast<decltype(object)>(user_data))..., static_cast<EngineHandle>(uc));
                };
                auto id = HookID{};
                auto const error = ffi::uc_hook_add(_uc,
                                                    reinterpret_cast<ffi::uc_hook*>(&id),
                                                    ffi::UC_HOOK_INSN_INVALID,
                                                    reinterpret_cast<void*>(trampoline),
                                                    utility::arg_or_nullptr(object...),
                                                    range.first,
                                                    range.last);
                return {(Error)error, {id, _uc}};
            }

            //! @brief Hook X86 SYSCALL instruction.
            //!
            //! @tparam function to invoke on callback
            //! @tparam optional ObjectT type to pass to function
            //! @param range of memory to hook in
            //! @param object pointer to pass to function as first argument
            template <auto function, typename... ObjectT>
            Result<Hook> add_insn_syscall(mem::Range range, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_insn_syscall_t trampoline = [](ffi::uc_engine* uc, void* user_data) -> void {
                    return std::invoke(
                        function, reinterpret_cast<ObjectT*>(user_data)..., static_cast<EngineHandle>(uc));
                };
                auto id = HookID{};
                auto const error = ffi::uc_hook_add(_uc,
                                                    reinterpret_cast<ffi::uc_hook*>(&id),
                                                    ffi::UC_HOOK_INSN,
                                                    reinterpret_cast<void*>(trampoline),
                                                    utility::arg_or_nullptr(object...),
                                                    range.first,
                                                    range.last,
                                                    ffi::UC_X86_INS_SYSCALL);
                return {(Error)error, {id, _uc}};
            }

            //! @brief Hook X86 SYSENTER instruction.
            //!
            //! @tparam function to invoke on callback
            //! @tparam optional ObjectT type to pass to function
            //! @param range of memory to hook in
            //! @param object pointer to pass to function as first argument
            template <auto function, typename... ObjectT>
            Result<Hook> add_insn_sysenter(mem::Range range, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_insn_syscall_t trampoline = [](ffi::uc_engine* uc, void* user_data) -> void {
                    return std::invoke(
                        function, reinterpret_cast<ObjectT*>(user_data)..., static_cast<EngineHandle>(uc));
                };
                auto id = HookID{};
                auto const error = ffi::uc_hook_add(_uc,
                                                    reinterpret_cast<ffi::uc_hook*>(&id),
                                                    ffi::UC_HOOK_INSN,
                                                    reinterpret_cast<void*>(trampoline),
                                                    utility::arg_or_nullptr(object...),
                                                    range.first,
                                                    range.last,
                                                    ffi::UC_X86_INS_SYSENTER);
                return {(Error)error, {id, _uc}};
            }

            //! @brief Hook X86 CPUID instruction.
            //!
            //! @tparam function to invoke on callback
            //! @tparam optional ObjectT type to pass to function
            //! @param range of memory to hook in
            //! @param object pointer to pass to function as first argument
            template <auto function, typename... ObjectT>
            Result<Hook> add_insn_cpuid(mem::Range range, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_insn_cpuid_t trampoline = [](ffi::uc_engine* uc, void* user_data) -> int {
                    return std::invoke(
                        function, reinterpret_cast<ObjectT*>(user_data)..., static_cast<EngineHandle>(uc));
                };
                auto id = HookID{};
                auto const error = ffi::uc_hook_add(_uc,
                                                    reinterpret_cast<ffi::uc_hook*>(&id),
                                                    ffi::UC_HOOK_INSN,
                                                    reinterpret_cast<void*>(trampoline),
                                                    utility::arg_or_nullptr(object...),
                                                    range.first,
                                                    range.last,
                                                    ffi::UC_X86_INS_CPUID);
                return {(Error)error, {id, _uc}};
            }

            //! @brief Hook X86 IN instruction.
            //!
            //! @tparam function to invoke on callback
            //! @tparam optional ObjectT type to pass to function
            //! @param range of memory to hook in
            //! @param object pointer to pass to function as first argument
            template <auto function, typename... ObjectT>
            Result<Hook> add_insn_in(mem::Range range, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_insn_in_t trampoline =
                    [](ffi::uc_engine* uc, std::uint32_t port, int size, void* user_data) -> std::uint32_t {
                    return std::invoke(function,
                                       reinterpret_cast<ObjectT*>(user_data)...,
                                       static_cast<EngineHandle>(uc),
                                       static_cast<std::uint32_t>(port),
                                       static_cast<std::size_t>(size));
                };
                auto id = HookID{};
                auto const error = ffi::uc_hook_add(_uc,
                                                    reinterpret_cast<ffi::uc_hook*>(&id),
                                                    ffi::UC_HOOK_INSN,
                                                    reinterpret_cast<void*>(trampoline),
                                                    utility::arg_or_nullptr(object...),
                                                    range.first,
                                                    range.last,
                                                    ffi::UC_X86_INS_IN);
                return {(Error)error, {id, _uc}};
            }

            //! @brief Hook X86 OUT instruction.
            //!
            //! @tparam function to invoke on callback
            //! @tparam optional ObjectT type to pass to function
            //! @param range of memory to hook in
            //! @param object pointer to pass to function as first argument
            template <auto function, typename... ObjectT>
            Result<Hook> add_insn_out(mem::Range range, ObjectT*... object) const noexcept {
                constexpr ffi::uc_cb_insn_out_t trampoline =
                    [](ffi::uc_engine* uc, std::uint32_t port, int size, std::uint32_t value, void* user_data) -> void {
                    return std::invoke(function,
                                       reinterpret_cast<ObjectT*>(user_data)...,
                                       static_cast<EngineHandle>(uc),
                                       static_cast<std::uint32_t>(port),
                                       static_cast<std::size_t>(size),
                                       static_cast<std::uint32_t>(value));
                };
                auto id = HookID{};
                auto const error = ffi::uc_hook_add(_uc,
                                                    reinterpret_cast<ffi::uc_hook*>(&id),
                                                    ffi::UC_HOOK_INSN,
                                                    reinterpret_cast<void*>(trampoline),
                                                    utility::arg_or_nullptr(object...),
                                                    range.first,
                                                    range.last,
                                                    ffi::UC_X86_INS_OUT);
                return {(Error)error, {id, _uc}};
            }

            //! @brief Remove a unmanaged hook.
            //!
            //! @param id of hook to delete.
            Result<> del(HookID id) const noexcept {
                auto const error = ffi::uc_hook_del(_uc, (ffi::uc_hook)id);
                return {(Error)error};
            }
        };

        //! @brief Unified API for unicorn engine.
        union EngineAPI {
            //! @brief Internal handle to unicorn engine.
            ffi::uc_engine* _uc;

            //! @brief API instance for control operations.
            CtlAPI ctl;

            //! @brief API instance for query operations.
            QueryAPI query;

            //! @brief API instance for emulation operations.
            EmuAPI emu;

            //! @brief API instance for unciron engine memory.
            MemAPI mem;

            //! @brief API instance for unicorn engine hooks.
            HookAPI hook;

            //! @brief API instance for unicorn engine registers.
            RegsAPI reg;
        };

        //! @brief Constructs null handle.
        EngineHandle() noexcept : api_{nullptr} {}

        //! @brief Constructs handle from raw unicorn engine pointer explicitly.
        explicit EngineHandle(ffi::uc_engine* uc) noexcept : api_{uc} {}

        //! @brief Get ffi engine handle
        explicit operator ffi::uc_engine*() const noexcept { return api_._uc; }

        //! @brief Access engine handle API.
        EngineAPI const* operator->() const noexcept { return &api_; }

        //! @brief Checks if two handles are equal.
        bool operator==(EngineHandle rhs) const noexcept { return api_._uc == rhs.api_._uc; }

        //! @brief Check if two handles are not equal.
        bool operator!=(EngineHandle rhs) const noexcept { return api_._uc != rhs.api_._uc; }

        //! @brief Checks if handle is valid (not null).
        explicit operator bool() const noexcept { return api_._uc != nullptr; }

        //! @brief Checks if handle is not valid(null).
        bool operator!() const noexcept { return api_._uc == nullptr; }

        //! @brief Open new unmanaged unicorn handle.
        static Result<EngineHandle> open(Mode mode) noexcept {
            auto uc = (ffi::uc_engine*)nullptr;
            auto const error = ffi::uc_open(Arch::ARCH, (ffi::uc_mode)(Arch::MODE_INIT | mode), &uc);
            return {(Error)error, EngineHandle{uc}};
        }

        //! @brief Closes unicorn handle.
        Result<> close() noexcept {
            if (auto const uc = std::exchange(api_._uc, nullptr)) {
                auto const error = ffi::uc_close(uc);
                return {(Error)error};
            }
            return {Error::OK};
        }

    private:
        EngineAPI api_;
    };

    //! @brief Owned handle for unicorn engine instance.
    //!
    //! @tparam Arch type of engine architecture.
    template <typename Arch>
    struct EngineOwner : EngineHandle<Arch> {
        //! @brief Unowned engine handle alias.
        using EngineHandle = EngineHandle<Arch>;

        //! @brief Architecture specific CPU model.
        using CPU = typename EngineHandle::CPU;

        //! @brief API for unicorn engine registers.
        using Mode = typename EngineHandle::Mode;

        //! @brief Unified API for unicorn engine.
        using EngineAPI = typename EngineHandle::EngineAPI;

        using EngineHandle::close;
        using EngineHandle::open;
        using EngineHandle::operator uc::ffi::uc_engine*;
        using EngineHandle::operator bool;
        using EngineHandle::operator!;
        using EngineHandle::operator!=;
        using EngineHandle::operator==;
        using EngineHandle::operator->;

        //! @brief Convert unmanaged handle to owned engine handle.
        explicit EngineOwner(EngineHandle handle) noexcept : EngineHandle{handle} {}

        //! @brief Construct null.
        EngineOwner() noexcept : EngineHandle{} {}

        //! @brief Can not be copy constructed.
        EngineOwner(EngineOwner const& other) = delete;

        //! @brief Move construct from other.
        EngineOwner(EngineOwner&& other) noexcept : EngineHandle(std::exchange((EngineHandle&)other, EngineHandle{})) {}

        //! @brief Move assign from other.
        EngineOwner& operator=(EngineOwner other) noexcept {
            std::swap((EngineHandle&)*this, (EngineHandle&)other);
            return *this;
        }

        //! @brief Cleanup.
        ~EngineOwner() noexcept { (void)this->close(); }

        //! @brief Try to construct owned engine handle.
        //!
        //! @note Throws Exception if failed.
        explicit EngineOwner(Mode mode, char const* why = "", Location where = Location::current()) noexcept(false)
            : EngineOwner(EngineHandle::open(mode).expect(why, where)) {}

        //! @brief Converting owned handle to unowned handle transfers ownership.
        explicit operator EngineHandle() && noexcept { return std::exchange((EngineHandle&)*this, EngineHandle{}); }
    };

    //! @brief CPU context handle.
    //!
    //! @brief Used for saving and restoring snapshots of registers.
    template <typename Arch>
    struct Context {
        //! @brief Construct null.
        Context() noexcept : ctx_{nullptr} {}

        //! @brief Can not be copy constructed.
        Context(Context const&) = delete;

        //! @brief Move construct.
        Context(Context&& other) noexcept : ctx_(std::exchange(other.ctx_, nullptr)) {}

        //! @brief Move assign.
        Context& operator=(Context other) noexcept {
            std::swap(ctx_, other.ctx_);
            return *this;
        }

        //! @brief Cleanup.
        ~Context() noexcept { (void)this->close(); }

        //! @brief Construct and save context.
        explicit Context(EngineHandle<Arch> handle,
                         char const* why = "",
                         Location where = Location::current()) noexcept(false)
            : ctx_{nullptr} {
            save(handle).expect(why, where);
        }

        //! @brief Check if context is initialized.
        explicit operator bool() const noexcept { return ctx_ != nullptr; }

        //! @brief Check if context is not initialized.
        bool operator!() const noexcept { return ctx_ == nullptr; }

        //! @brief Initialize context.
        Result<> init(EngineHandle<Arch> handle) noexcept {
            if (!handle) {
                return {error::ERR_HANDLE, {}};
            }
            if (!ctx_) {
                auto const error = ffi::uc_context_alloc((ffi::uc_engine*)handle, &ctx_);
                return {(Error)error};
            }
            return {};
        }

        //! @brief Save context.
        Result<> save(EngineHandle<Arch> handle) noexcept {
            if (auto const result = this->init(handle); !result) {
                return result;
            }
            auto const error = ffi::uc_context_save((ffi::uc_engine*)handle, ctx_);
            return {(Error)error};
        }

        //! @brief Restore context.
        Result<> restore(EngineHandle<Arch> handle) noexcept {
            if (!handle || !ctx_) {
                return {error::ERR_HANDLE, {}};
            }
            auto const error = ffi::uc_context_restore((ffi::uc_engine*)handle, ctx_);
            return {(Error)error};
        }

        //! @brief Close context.
        Result<> close() noexcept {
            if (auto const ctx = std::exchange(ctx_, nullptr)) {
                auto const error = ffi::uc_context_free(ctx);
                return {(Error)error};
            }
            return {Error::OK};
        }

    private:
        //! @brief Internal context pointer.
        ffi::uc_context* ctx_;
    };
}

//! @section Arcitectures
namespace uc {
#ifndef UNICORN_HPP_NO_ARM32
    //! @brief ARM architecture.
    struct ARM32 {
        //! @brief Raw unicorn architecture ID.
        static constexpr inline auto ARCH = ffi::UC_ARCH_ARM;

        //! @brief Mode flags.
        enum Mode : unsigned {
            MODE_INIT = 0,                         ///< Implicit mode flags for engine creation.
            MODE_LE = ffi::UC_MODE_LITTLE_ENDIAN,  ///< Little-endian mode (default mode).
            MODE_BE = ffi::UC_MODE_BIG_ENDIAN,     ///< Big-endian mode.
            MODE_ARM = ffi::UC_MODE_THUMB,         ///< ARM mode (default mode).
            MODE_THUMB = ffi::UC_MODE_THUMB,       ///< THUMB mode (including Thumb-2).
        };

        //! @brief CPU Type.
        enum CPU : unsigned {
            CPU_DEFAULT = (unsigned)-1,
            CPU_926 = ffi::UC_CPU_ARM_926,
            CPU_946 = ffi::UC_CPU_ARM_946,
            CPU_1026 = ffi::UC_CPU_ARM_1026,
            CPU_1136_R2 = ffi::UC_CPU_ARM_1136_R2,
            CPU_1136 = ffi::UC_CPU_ARM_1136,
            CPU_1176 = ffi::UC_CPU_ARM_1176,
            CPU_11MPCORE = ffi::UC_CPU_ARM_11MPCORE,
            CPU_CORTEX_M0 = ffi::UC_CPU_ARM_CORTEX_M0,
            CPU_CORTEX_M3 = ffi::UC_CPU_ARM_CORTEX_M3,
            CPU_CORTEX_M4 = ffi::UC_CPU_ARM_CORTEX_M4,
            CPU_CORTEX_M7 = ffi::UC_CPU_ARM_CORTEX_M7,
            CPU_CORTEX_M33 = ffi::UC_CPU_ARM_CORTEX_M33,
            CPU_CORTEX_R5 = ffi::UC_CPU_ARM_CORTEX_R5,
            CPU_CORTEX_R5F = ffi::UC_CPU_ARM_CORTEX_R5F,
            CPU_CORTEX_A7 = ffi::UC_CPU_ARM_CORTEX_A7,
            CPU_CORTEX_A8 = ffi::UC_CPU_ARM_CORTEX_A8,
            CPU_CORTEX_A9 = ffi::UC_CPU_ARM_CORTEX_A9,
            CPU_CORTEX_A15 = ffi::UC_CPU_ARM_CORTEX_A15,
            CPU_TI925T = ffi::UC_CPU_ARM_TI925T,
            CPU_SA1100 = ffi::UC_CPU_ARM_SA1100,
            CPU_SA1110 = ffi::UC_CPU_ARM_SA1110,
            CPU_PXA250 = ffi::UC_CPU_ARM_PXA250,
            CPU_PXA255 = ffi::UC_CPU_ARM_PXA255,
            CPU_PXA260 = ffi::UC_CPU_ARM_PXA260,
            CPU_PXA261 = ffi::UC_CPU_ARM_PXA261,
            CPU_PXA262 = ffi::UC_CPU_ARM_PXA262,
            CPU_PXA270 = ffi::UC_CPU_ARM_PXA270,
            CPU_PXA270A0 = ffi::UC_CPU_ARM_PXA270A0,
            CPU_PXA270A1 = ffi::UC_CPU_ARM_PXA270A1,
            CPU_PXA270B0 = ffi::UC_CPU_ARM_PXA270B0,
            CPU_PXA270B1 = ffi::UC_CPU_ARM_PXA270B1,
            CPU_PXA270C0 = ffi::UC_CPU_ARM_PXA270C0,
            CPU_PXA270C5 = ffi::UC_CPU_ARM_PXA270C5,
        };

        //! @brief ARM registers API.
        union RegsAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            mem::Register<std::uint32_t, ffi::UC_ARM_REG_PC> pc;  ///< reg.

            mem::Register<std::uint32_t, ffi::UC_ARM_REG_APSR> apsr;              ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_APSR_NZCV> apsr_nzcv;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_CPSR> cpsr;              ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_FPEXC> fpexc;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_FPINST> fpinst;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_FPSCR> fpscr;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_FPSCR_NZCV> fpscr_nzcv;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_FPSID> fpsid;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_ITSTATE> itstate;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_LR> lr;                  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_SP> sp;                  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_SPSR> spsr;              ///< reg.

            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D0> d0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D1> d1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D2> d2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D3> d3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D4> d4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D5> d5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D6> d6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D7> d7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D8> d8;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D9> d9;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D10> d10;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D11> d11;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D12> d12;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D13> d13;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D14> d14;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D15> d15;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D16> d16;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D17> d17;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D18> d18;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D19> d19;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D20> d20;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D21> d21;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D22> d22;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D23> d23;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D24> d24;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D25> d25;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D26> d26;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D27> d27;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D28> d28;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D29> d29;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D30> d30;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM_REG_D31> d31;  ///< reg.

            mem::Register<std::uint32_t, ffi::UC_ARM_REG_FPINST2> fpinst2;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_MVFR0> mvfr0;      ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_MVFR1> mvfr1;      ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_MVFR2> mvfr2;      ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q0> q0;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q1> q1;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q2> q2;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q3> q3;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q4> q4;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q5> q5;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q6> q6;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q7> q7;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q8> q8;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q9> q9;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q10> q10;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q11> q11;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q12> q12;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q13> q13;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q14> q14;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_Q15> q15;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R0> r0;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R1> r1;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R2> r2;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R3> r3;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R4> r4;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R5> r5;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R6> r6;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R7> r7;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R8> r8;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R9> r9;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R10> r10;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R11> r11;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R12> r12;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S0> s0;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S1> s1;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S2> s2;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S3> s3;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S4> s4;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S5> s5;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S6> s6;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S7> s7;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S8> s8;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S9> s9;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S10> s10;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S11> s11;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S12> s12;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S13> s13;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S14> s14;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S15> s15;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S16> s16;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S17> s17;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S18> s18;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S19> s19;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S20> s20;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S21> s21;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S22> s22;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S23> s23;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S24> s24;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S25> s25;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S26> s26;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S27> s27;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S28> s28;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S29> s29;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S30> s30;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_S31> s31;          ///< reg.

            mem::Register<std::uint32_t, ffi::UC_ARM_REG_C1_C0_2> c1_c0_2;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_C13_C0_2> c13_c0_2;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_C13_C0_3> c13_c0_3;  ///< reg.

            mem::Register<std::uint32_t, ffi::UC_ARM_REG_IPSR> ipsr;                  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_MSP> msp;                    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_PSP> psp;                    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_CONTROL> control;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_IAPSR> iapsr;                ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_EAPSR> eapsr;                ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_XPSR> xpsr;                  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_EPSR> epsr;                  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_IEPSR> iepsr;                ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_PRIMASK> primask;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_BASEPRI> basepri;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_BASEPRI_MAX> basepri_max;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_FAULTMASK> faultmask;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_APSR_NZCVQ> apsr_nzcvq;      ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_APSR_G> apsr_g;              ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_APSR_NZCVQG> apsr_nzcvqg;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_IAPSR_NZCVQ> iapsr_nzcvq;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_IAPSR_G> iapsr_g;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_IAPSR_NZCVQG> iapsr_nzcvqg;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_EAPSR_NZCVQ> eapsr_nzcvq;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_EAPSR_G> eapsr_g;            ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_EAPSR_NZCVQG> eapsr_nzcvqg;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_XPSR_NZCVQ> xpsr_nzcvq;      ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_XPSR_G> xpsr_g;              ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_XPSR_NZCVQG> xpsr_nzcvqg;    ///< reg.

            //> alias registers
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R13> r13;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R14> r14;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_R15> r15;  ///< reg.

            mem::Register<std::uint32_t, ffi::UC_ARM_REG_SB> sb;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_SL> sl;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM_REG_FP> fp;  ///< reg.
        };
    };
    //! @brief Implement Architecture interface for ARM32.
    UNICORN_HPP_IMPL_ARCH(ARM32);
#endif

#ifndef UNICORN_HPP_NO_ARM64
    //! @brief ARM64(AArch64) architecture.
    struct ARM64 {
        //! @brief Raw unicorn architecture ID.
        static constexpr inline auto ARCH = ffi::UC_ARCH_ARM64;

        //! @brief Mode flags.
        enum Mode : unsigned {
            MODE_INIT = 0,                         ///< Implicit mode flags for engine creation.
            MODE_LE = ffi::UC_MODE_LITTLE_ENDIAN,  ///< Little-endian mode (default mode).
            MODE_BE = ffi::UC_MODE_BIG_ENDIAN,     ///< Big-endian mode.
            MODE_ARM = ffi::UC_MODE_THUMB,         ///< ARM mode (default mode).
            MODE_THUMB = ffi::UC_MODE_THUMB,       ///< THUMB mode (including Thumb-2).
        };

        //! @brief CPU Type.
        enum CPU : unsigned {
            CPU_DEFAULT = (unsigned)-1,
            CPU_A57 = ffi::UC_CPU_AARCH64_A57,
            CPU_A53 = ffi::UC_CPU_AARCH64_A53,
            CPU_A72 = ffi::UC_CPU_AARCH64_A72,
        };

        //! @brief ARM64 registers API.
        union RegsAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            //> pseudo registers
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_PC> pc;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X29> x29;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X30> x30;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_NZCV> nzcv;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_SP> sp;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_WSP> wsp;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_WZR> wzr;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_XZR> xzr;    ///< reg.

            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B0> b0;    ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B1> b1;    ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B2> b2;    ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B3> b3;    ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B4> b4;    ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B5> b5;    ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B6> b6;    ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B7> b7;    ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B8> b8;    ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B9> b9;    ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B10> b10;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B11> b11;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B12> b12;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B13> b13;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B14> b14;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B15> b15;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B16> b16;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B17> b17;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B18> b18;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B19> b19;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B20> b20;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B21> b21;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B22> b22;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B23> b23;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B24> b24;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B25> b25;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B26> b26;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B27> b27;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B28> b28;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B29> b29;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B30> b30;  ///< reg.
            mem::Register<std::uint8_t, ffi::UC_ARM64_REG_B31> b31;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D0> d0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D1> d1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D2> d2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D3> d3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D4> d4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D5> d5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D6> d6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D7> d7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D8> d8;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D9> d9;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D10> d10;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D11> d11;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D12> d12;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D13> d13;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D14> d14;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D15> d15;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D16> d16;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D17> d17;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D18> d18;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D19> d19;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D20> d20;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D21> d21;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D22> d22;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D23> d23;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D24> d24;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D25> d25;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D26> d26;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D27> d27;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D28> d28;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D29> d29;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D30> d30;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_D31> d31;  ///< reg.

            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H0> h0;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H1> h1;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H2> h2;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H3> h3;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H4> h4;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H5> h5;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H6> h6;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H7> h7;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H8> h8;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H9> h9;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H10> h10;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H11> h11;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H12> h12;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H13> h13;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H14> h14;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H15> h15;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H16> h16;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H17> h17;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H18> h18;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H19> h19;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H20> h20;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H21> h21;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H22> h22;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H23> h23;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H24> h24;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H25> h25;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H26> h26;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H27> h27;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H28> h28;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H29> h29;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H30> h30;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_ARM64_REG_H31> h31;  ///< reg.

            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q0> q0;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q1> q1;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q2> q2;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q3> q3;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q4> q4;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q5> q5;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q6> q6;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q7> q7;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q8> q8;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q9> q9;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q10> q10;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q11> q11;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q12> q12;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q13> q13;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q14> q14;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q15> q15;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q16> q16;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q17> q17;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q18> q18;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q19> q19;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q20> q20;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q21> q21;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q22> q22;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q23> q23;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q24> q24;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q25> q25;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q26> q26;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q27> q27;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q28> q28;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q29> q29;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q30> q30;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_Q31> q31;  ///< reg.

            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S0> s0;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S1> s1;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S2> s2;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S3> s3;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S4> s4;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S5> s5;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S6> s6;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S7> s7;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S8> s8;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S9> s9;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S10> s10;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S11> s11;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S12> s12;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S13> s13;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S14> s14;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S15> s15;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S16> s16;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S17> s17;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S18> s18;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S19> s19;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S20> s20;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S21> s21;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S22> s22;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S23> s23;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S24> s24;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S25> s25;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S26> s26;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S27> s27;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S28> s28;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S29> s29;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S30> s30;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_S31> s31;  ///< reg.

            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W0> w0;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W1> w1;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W2> w2;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W3> w3;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W4> w4;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W5> w5;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W6> w6;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W7> w7;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W8> w8;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W9> w9;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W10> w10;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W11> w11;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W12> w12;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W13> w13;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W14> w14;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W15> w15;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W16> w16;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W17> w17;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W18> w18;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W19> w19;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W20> w20;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W21> w21;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W22> w22;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W23> w23;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W24> w24;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W25> w25;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W26> w26;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W27> w27;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W28> w28;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W29> w29;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_W30> w30;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X0> x0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X1> x1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X2> x2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X3> x3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X4> x4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X5> x5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X6> x6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X7> x7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X8> x8;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X9> x9;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X10> x10;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X11> x11;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X12> x12;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X13> x13;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X14> x14;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X15> x15;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X16> x16;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X17> x17;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X18> x18;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X19> x19;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X20> x20;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X21> x21;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X22> x22;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X23> x23;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X24> x24;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X25> x25;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X26> x26;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X27> x27;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_X28> x28;  ///< reg.

            mem::Register<mem::U128, ffi::UC_ARM64_REG_V0> v0;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V1> v1;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V2> v2;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V3> v3;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V4> v4;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V5> v5;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V6> v6;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V7> v7;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V8> v8;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V9> v9;    ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V10> v10;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V11> v11;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V12> v12;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V13> v13;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V14> v14;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V15> v15;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V16> v16;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V17> v17;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V18> v18;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V19> v19;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V20> v20;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V21> v21;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V22> v22;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V23> v23;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V24> v24;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V25> v25;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V26> v26;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V27> v27;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V28> v28;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V29> v29;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V30> v30;  ///< reg.
            mem::Register<mem::U128, ffi::UC_ARM64_REG_V31> v31;  ///< reg.

            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_CPACR_EL1> cpacr_el1;  ///< reg.

            //> thread registers
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_TPIDR_EL0> tpidr_el0;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_TPIDRRO_EL0> tpidrro_el0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_TPIDR_EL1> tpidr_el1;      ///< reg.

            mem::Register<std::uint32_t, ffi::UC_ARM64_REG_PSTATE> pstate;  ///< reg.

            //> exception link registers
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_ELR_EL0> elr_el0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_ELR_EL1> elr_el1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_ELR_EL2> elr_el2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_ELR_EL3> elr_el3;  ///< reg.

            //> stack pointers registers
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_SP_EL0> sp_el0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_SP_EL1> sp_el1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_SP_EL2> sp_el2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_SP_EL3> sp_el3;  ///< reg.

            //> other CP15 registers
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_TTBR0_EL1> ttbr0_el1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_TTBR1_EL1> ttbr1_el1;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_ESR_EL0> esr_el0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_ESR_EL1> esr_el1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_ESR_EL2> esr_el2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_ESR_EL3> esr_el3;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_FAR_EL0> far_el0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_FAR_EL1> far_el1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_FAR_EL2> far_el2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_FAR_EL3> far_el3;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_PAR_EL1> par_el1;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_MAIR_EL1> mair_el1;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_VBAR_EL0> vbar_el0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_VBAR_EL1> vbar_el1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_VBAR_EL2> vbar_el2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_VBAR_EL3> vbar_el3;  ///< reg.

            //> alias registers

            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_IP0> ip0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_IP1> ip1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_FP> fp;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_ARM64_REG_LR> lr;    ///< reg.
        };
    };
    //! @brief Implement Architecture interface for ARM64.
    UNICORN_HPP_IMPL_ARCH(ARM64);
#endif

#ifndef UNICORN_HPP_NO_M68K
    //! @brief M68K architecutre.
    struct M68K {
        //! @brief Raw unicorn architecture ID.
        static constexpr inline auto ARCH = ffi::UC_ARCH_M68K;

        //! @brief Mode flags.
        enum Mode : unsigned {
            MODE_INIT = 0,                      ///< Implicit mode flags for engine creation.
            MODE_BE = ffi::UC_MODE_BIG_ENDIAN,  ///< Big-endian mode.
        };

        //! @brief CPU Type.
        enum CPU : unsigned {
            CPU_DEFAULT = (unsigned)-1,
            CPU_M5206 = ffi::UC_CPU_M68K_M5206,
            CPU_M68000 = ffi::UC_CPU_M68K_M68000,
            CPU_M68020 = ffi::UC_CPU_M68K_M68020,
            CPU_M68030 = ffi::UC_CPU_M68K_M68030,
            CPU_M68040 = ffi::UC_CPU_M68K_M68040,
            CPU_M68060 = ffi::UC_CPU_M68K_M68060,
            CPU_M5208 = ffi::UC_CPU_M68K_M5208,
            CPU_CFV4E = ffi::UC_CPU_M68K_CFV4E,
            CPU_ANY = ffi::UC_CPU_M68K_ANY,
        };

        //! @brief M68K registers API.
        union RegsAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            mem::Register<std::uint32_t, ffi::UC_M68K_REG_PC> pc;  ///< reg.

            mem::Register<std::uint32_t, ffi::UC_M68K_REG_A0> a0;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_A1> a1;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_A2> a2;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_A3> a3;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_A4> a4;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_A5> a5;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_A6> a6;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_A7> a7;  ///< reg.

            mem::Register<std::uint32_t, ffi::UC_M68K_REG_D0> d0;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_D1> d1;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_D2> d2;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_D3> d3;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_D4> d4;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_D5> d5;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_D6> d6;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_M68K_REG_D7> d7;  ///< reg.
        };
    };
    //! @brief Implement Architecture interface for M68K.
    UNICORN_HPP_IMPL_ARCH(M68K);
#endif

#ifndef UNICORN_HPP_NO_MIPS32
    //! @brief Common definitions for MIPS32 & MIPS64 architecure.
    struct MIPS {
        //! @brief Raw unicorn architecture ID.
        static constexpr inline auto ARCH = ffi::UC_ARCH_MIPS;

        //! @brief MIPS registers API.
        union RegsAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_PC> pc;  ///< reg.

            //> General purpose registers
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_0> gpr0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_1> gpr1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_2> gpr2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_3> gpr3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_4> gpr4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_5> gpr5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_6> gpr6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_7> gpr7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_8> gpr8;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_9> gpr9;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_10> gpr10;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_11> gpr11;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_12> gpr12;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_13> gpr13;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_14> gpr14;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_15> gpr15;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_16> gpr16;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_17> gpr17;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_18> gpr18;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_19> gpr19;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_20> gpr20;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_21> gpr21;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_22> gpr22;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_23> gpr23;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_24> gpr24;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_25> gpr25;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_26> gpr26;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_27> gpr27;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_28> gpr28;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_29> gpr29;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_30> gpr30;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_31> gpr31;  ///< reg.

            //> DSP registers
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_DSPCCOND> dspccond;                ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_DSPCARRY> dspcarry;                ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_DSPEFI> dspefi;                    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_DSPOUTFLAG> dspoutflag;            ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_DSPOUTFLAG16_19> dspoutflag16_19;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_DSPOUTFLAG20> dspoutflag20;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_DSPOUTFLAG21> dspoutflag21;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_DSPOUTFLAG22> dspoutflag22;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_DSPOUTFLAG23> dspoutflag23;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_DSPPOS> dsppos;                    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_DSPSCOUNT> dspscount;              ///< reg.

            //> ACC registers
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_AC0> ac0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_AC1> ac1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_AC2> ac2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_AC3> ac3;  ///< reg.

            //> COP registers
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_CC0> cc0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_CC1> cc1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_CC2> cc2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_CC3> cc3;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_CC4> cc4;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_CC5> cc5;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_CC6> cc6;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_CC7> cc7;  ///< reg.

            //> FPU registers
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F0> f0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F1> f1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F2> f2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F3> f3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F4> f4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F5> f5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F6> f6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F7> f7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F8> f8;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F9> f9;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F10> f10;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F11> f11;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F12> f12;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F13> f13;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F14> f14;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F15> f15;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F16> f16;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F17> f17;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F18> f18;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F19> f19;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F20> f20;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F21> f21;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F22> f22;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F23> f23;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F24> f24;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F25> f25;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F26> f26;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F27> f27;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F28> f28;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F29> f29;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F30> f30;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_F31> f31;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_FCC0> fcc0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_FCC1> fcc1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_FCC2> fcc2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_FCC3> fcc3;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_FCC4> fcc4;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_FCC5> fcc5;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_FCC6> fcc6;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_FCC7> fcc7;  ///< reg.

            //> AFPR128
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W0> w0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W1> w1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W2> w2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W3> w3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W4> w4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W5> w5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W6> w6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W7> w7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W8> w8;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W9> w9;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W10> w10;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W11> w11;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W12> w12;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W13> w13;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W14> w14;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W15> w15;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W16> w16;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W17> w17;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W18> w18;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W19> w19;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W20> w20;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W21> w21;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W22> w22;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W23> w23;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W24> w24;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W25> w25;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W26> w26;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W27> w27;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W28> w28;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W29> w29;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W30> w30;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_W31> w31;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_HI> hi;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_LO> lo;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_P0> p0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_P1> p1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_P2> p2;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_MPL0> mpl0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_MPL1> mpl1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_MPL2> mpl2;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_CP0_CONFIG3> cp0_config3;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_CP0_USERLOCAL> cp0_userlocal;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_CP0_STATUS> cp0_status;        ///< reg.

            // alias registers
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_ZERO> zero;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_AT> at;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_V0> v0;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_V1> v1;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_A0> a0;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_A1> a1;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_A2> a2;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_A3> a3;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_T0> t0;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_T1> t1;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_T2> t2;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_T3> t3;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_T4> t4;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_T5> t5;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_T6> t6;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_T7> t7;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_S0> s0;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_S1> s1;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_S2> s2;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_S3> s3;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_S4> s4;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_S5> s5;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_S6> s6;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_S7> s7;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_T8> t8;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_T9> t9;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_K0> k0;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_K1> k1;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_GP> gp;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_SP> sp;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_FP> fp;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_S8> s8;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_RA> ra;      ///< reg.

            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_HI0> hi0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_HI1> hi1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_HI2> hi2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_HI3> hi3;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_LO0> lo0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_LO1> lo1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_LO2> lo2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_MIPS_REG_LO3> lo3;  ///< reg.
        };
    };

    //! @brief MIPS32 architecture.
    struct MIPS32 : MIPS {
        //! @brief Mode flags.
        enum Mode : unsigned {
            MODE_INIT = ffi::UC_MODE_MIPS32,       ///< Implicit mode flags for engine creation.
            MODE_LE = ffi::UC_MODE_LITTLE_ENDIAN,  ///< Little-endian mode (default mode).
            MODE_BE = ffi::UC_MODE_BIG_ENDIAN,     ///< Big-endian mode.
            MODE_32 = ffi::UC_MODE_MIPS32,         ///< 32bit mode.
        };

        //! @brief CPU Type.
        enum CPU : unsigned {
            CPU_DEFAULT = (unsigned)-1,
            CPU_4KC = ffi::UC_CPU_MIPS32_4KC,
            CPU_4KM = ffi::UC_CPU_MIPS32_4KM,
            CPU_4KECR1 = ffi::UC_CPU_MIPS32_4KECR1,
            CPU_4KEMR1 = ffi::UC_CPU_MIPS32_4KEMR1,
            CPU_4KEC = ffi::UC_CPU_MIPS32_4KEC,
            CPU_4KEM = ffi::UC_CPU_MIPS32_4KEM,
            CPU_24KC = ffi::UC_CPU_MIPS32_24KC,
            CPU_24KEC = ffi::UC_CPU_MIPS32_24KEC,
            CPU_24KF = ffi::UC_CPU_MIPS32_24KF,
            CPU_34KF = ffi::UC_CPU_MIPS32_34KF,
            CPU_74KF = ffi::UC_CPU_MIPS32_74KF,
            CPU_M14K = ffi::UC_CPU_MIPS32_M14K,
            CPU_M14KC = ffi::UC_CPU_MIPS32_M14KC,
            CPU_P5600 = ffi::UC_CPU_MIPS32_P5600,
            CPU_MIPS32R6_GENERIC = ffi::UC_CPU_MIPS32_MIPS32R6_GENERIC,
            CPU_I7200 = ffi::UC_CPU_MIPS32_I7200,
        };
    };
    //! @brief Implement Architecture interface for MIPS32.
    UNICORN_HPP_IMPL_ARCH(MIPS32);

    //! @brief MIPS64 architecture.
    struct MIPS64 : MIPS {
        //! @brief Mode flags.
        enum Mode : unsigned {
            MODE_INIT = ffi::UC_MODE_MIPS64,       ///< Implicit mode flags for engine creation.
            MODE_LE = ffi::UC_MODE_LITTLE_ENDIAN,  ///< Little-endian mode (default mode).
            MODE_BE = ffi::UC_MODE_BIG_ENDIAN,     ///< Big-endian mode.
            MODE_32 = ffi::UC_MODE_MIPS32,         ///< 32bit mode.
            MODE_64 = ffi::UC_MODE_MIPS64,         ///< 64bit mode.
        };

        //! @brief CPU Type.
        enum CPU : unsigned {
            CPU_DEFAULT = (unsigned)-1,
            CPU_R4000 = ffi::UC_CPU_MIPS64_R4000,
            CPU_VR5432 = ffi::UC_CPU_MIPS64_VR5432,
            CPU_5KC = ffi::UC_CPU_MIPS64_5KC,
            CPU_5KF = ffi::UC_CPU_MIPS64_5KF,
            CPU_20KC = ffi::UC_CPU_MIPS64_20KC,
            CPU_MIPS64R2_GENERIC = ffi::UC_CPU_MIPS64_MIPS64R2_GENERIC,
            CPU_5KEC = ffi::UC_CPU_MIPS64_5KEC,
            CPU_5KEF = ffi::UC_CPU_MIPS64_5KEF,
            CPU_I6400 = ffi::UC_CPU_MIPS64_I6400,
            CPU_I6500 = ffi::UC_CPU_MIPS64_I6500,
            CPU_LOONGSON_2E = ffi::UC_CPU_MIPS64_LOONGSON_2E,
            CPU_LOONGSON_2F = ffi::UC_CPU_MIPS64_LOONGSON_2F,
            CPU_MIPS64DSPR2 = ffi::UC_CPU_MIPS64_MIPS64DSPR2,
        };
    };
    //! @brief Implement Architecture interface for MIPS64.
    UNICORN_HPP_IMPL_ARCH(MIPS64);
#endif

#ifndef UNICORN_HPP_NO_PPC
    //! @brief Common definitions for PPC32 & PPC64 architecure.
    struct PPC {
        //! @brief Raw unicorn architecture ID.
        static constexpr inline auto ARCH = ffi::UC_ARCH_PPC;

        //! @brief PowerPC registers API.
        union RegsAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            mem::Register<std::uint64_t, ffi::UC_PPC_REG_PC> pc;  ///< reg.

            // General purpose registers
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_0> gpr0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_1> gpr1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_2> gpr2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_3> gpr3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_4> gpr4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_5> gpr5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_6> gpr6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_7> gpr7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_8> gpr8;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_9> gpr9;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_10> gpr10;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_11> gpr11;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_12> gpr12;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_13> gpr13;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_14> gpr14;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_15> gpr15;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_16> gpr16;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_17> gpr17;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_18> gpr18;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_19> gpr19;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_20> gpr20;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_21> gpr21;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_22> gpr22;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_23> gpr23;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_24> gpr24;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_25> gpr25;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_26> gpr26;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_27> gpr27;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_28> gpr28;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_29> gpr29;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_30> gpr30;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_PPC_REG_31> gpr31;  ///< reg.
        };
    };

    //! @brief PPC32 architecture.
    struct PPC32 : PPC {
        //! @brief Mode flags.
        enum Mode : unsigned {
            MODE_INIT = ffi::UC_MODE_PPC32,        ///< Implicit mode flags for engine creation.
            MODE_LE = ffi::UC_MODE_LITTLE_ENDIAN,  ///< Little-endian mode (default mode).
            MODE_BE = ffi::UC_MODE_BIG_ENDIAN,     ///< Big-endian mode.
            MODE_32 = ffi::UC_MODE_PPC32,          ///< 32bit mode.
        };

        //! @brief CPU Type.
        enum CPU : unsigned {
            CPU_DEFAULT = (unsigned)-1,
            CPU_401 = ffi::UC_CPU_PPC_401,
            CPU_401A1 = ffi::UC_CPU_PPC_401A1,
            CPU_401B2 = ffi::UC_CPU_PPC_401B2,
            CPU_401C2 = ffi::UC_CPU_PPC_401C2,
            CPU_401D2 = ffi::UC_CPU_PPC_401D2,
            CPU_401E2 = ffi::UC_CPU_PPC_401E2,
            CPU_401F2 = ffi::UC_CPU_PPC_401F2,
            CPU_401G2 = ffi::UC_CPU_PPC_401G2,
            CPU_IOP480 = ffi::UC_CPU_PPC_IOP480,
            CPU_COBRA = ffi::UC_CPU_PPC_COBRA,
            CPU_403GA = ffi::UC_CPU_PPC_403GA,
            CPU_403GB = ffi::UC_CPU_PPC_403GB,
            CPU_403GC = ffi::UC_CPU_PPC_403GC,
            CPU_403GCX = ffi::UC_CPU_PPC_403GCX,
            CPU_405D2 = ffi::UC_CPU_PPC_405D2,
            CPU_405D4 = ffi::UC_CPU_PPC_405D4,
            CPU_405CRA = ffi::UC_CPU_PPC_405CRA,
            CPU_405CRB = ffi::UC_CPU_PPC_405CRB,
            CPU_405CRC = ffi::UC_CPU_PPC_405CRC,
            CPU_405EP = ffi::UC_CPU_PPC_405EP,
            CPU_405EZ = ffi::UC_CPU_PPC_405EZ,
            CPU_405GPA = ffi::UC_CPU_PPC_405GPA,
            CPU_405GPB = ffi::UC_CPU_PPC_405GPB,
            CPU_405GPC = ffi::UC_CPU_PPC_405GPC,
            CPU_405GPD = ffi::UC_CPU_PPC_405GPD,
            CPU_405GPR = ffi::UC_CPU_PPC_405GPR,
            CPU_405LP = ffi::UC_CPU_PPC_405LP,
            CPU_NPE405H = ffi::UC_CPU_PPC_NPE405H,
            CPU_NPE405H2 = ffi::UC_CPU_PPC_NPE405H2,
            CPU_NPE405L = ffi::UC_CPU_PPC_NPE405L,
            CPU_NPE4GS3 = ffi::UC_CPU_PPC_NPE4GS3,
            CPU_STB03 = ffi::UC_CPU_PPC_STB03,
            CPU_STB04 = ffi::UC_CPU_PPC_STB04,
            CPU_STB25 = ffi::UC_CPU_PPC_STB25,
            CPU_X2VP4 = ffi::UC_CPU_PPC_X2VP4,
            CPU_X2VP20 = ffi::UC_CPU_PPC_X2VP20,
            CPU_440_XILINX = ffi::UC_CPU_PPC_440_XILINX,
            CPU_440_XILINX_W_DFPU = ffi::UC_CPU_PPC_440_XILINX_W_DFPU,
            CPU_440EPA = ffi::UC_CPU_PPC_440EPA,
            CPU_440EPB = ffi::UC_CPU_PPC_440EPB,
            CPU_440EPX = ffi::UC_CPU_PPC_440EPX,
            CPU_460EXB = ffi::UC_CPU_PPC_460EXB,
            CPU_G2 = ffi::UC_CPU_PPC_G2,
            CPU_G2H4 = ffi::UC_CPU_PPC_G2H4,
            CPU_G2GP = ffi::UC_CPU_PPC_G2GP,
            CPU_G2LS = ffi::UC_CPU_PPC_G2LS,
            CPU_G2HIP3 = ffi::UC_CPU_PPC_G2HIP3,
            CPU_G2HIP4 = ffi::UC_CPU_PPC_G2HIP4,
            CPU_MPC603 = ffi::UC_CPU_PPC_MPC603,
            CPU_G2LE = ffi::UC_CPU_PPC_G2LE,
            CPU_G2LEGP = ffi::UC_CPU_PPC_G2LEGP,
            CPU_G2LELS = ffi::UC_CPU_PPC_G2LELS,
            CPU_G2LEGP1 = ffi::UC_CPU_PPC_G2LEGP1,
            CPU_G2LEGP3 = ffi::UC_CPU_PPC_G2LEGP3,
            CPU_MPC5200_V10 = ffi::UC_CPU_PPC_MPC5200_V10,
            CPU_MPC5200_V11 = ffi::UC_CPU_PPC_MPC5200_V11,
            CPU_MPC5200_V12 = ffi::UC_CPU_PPC_MPC5200_V12,
            CPU_MPC5200B_V20 = ffi::UC_CPU_PPC_MPC5200B_V20,
            CPU_MPC5200B_V21 = ffi::UC_CPU_PPC_MPC5200B_V21,
            CPU_E200Z5 = ffi::UC_CPU_PPC_E200Z5,
            CPU_E200Z6 = ffi::UC_CPU_PPC_E200Z6,
            CPU_E300C1 = ffi::UC_CPU_PPC_E300C1,
            CPU_E300C2 = ffi::UC_CPU_PPC_E300C2,
            CPU_E300C3 = ffi::UC_CPU_PPC_E300C3,
            CPU_E300C4 = ffi::UC_CPU_PPC_E300C4,
            CPU_MPC8343 = ffi::UC_CPU_PPC_MPC8343,
            CPU_MPC8343A = ffi::UC_CPU_PPC_MPC8343A,
            CPU_MPC8343E = ffi::UC_CPU_PPC_MPC8343E,
            CPU_MPC8343EA = ffi::UC_CPU_PPC_MPC8343EA,
            CPU_MPC8347T = ffi::UC_CPU_PPC_MPC8347T,
            CPU_MPC8347P = ffi::UC_CPU_PPC_MPC8347P,
            CPU_MPC8347AT = ffi::UC_CPU_PPC_MPC8347AT,
            CPU_MPC8347AP = ffi::UC_CPU_PPC_MPC8347AP,
            CPU_MPC8347ET = ffi::UC_CPU_PPC_MPC8347ET,
            CPU_MPC8347EP = ffi::UC_CPU_PPC_MPC8347EP,
            CPU_MPC8347EAT = ffi::UC_CPU_PPC_MPC8347EAT,
            CPU_MPC8347EAP = ffi::UC_CPU_PPC_MPC8347EAP,
            CPU_MPC8349 = ffi::UC_CPU_PPC_MPC8349,
            CPU_MPC8349A = ffi::UC_CPU_PPC_MPC8349A,
            CPU_MPC8349E = ffi::UC_CPU_PPC_MPC8349E,
            CPU_MPC8349EA = ffi::UC_CPU_PPC_MPC8349EA,
            CPU_MPC8377 = ffi::UC_CPU_PPC_MPC8377,
            CPU_MPC8377E = ffi::UC_CPU_PPC_MPC8377E,
            CPU_MPC8378 = ffi::UC_CPU_PPC_MPC8378,
            CPU_MPC8378E = ffi::UC_CPU_PPC_MPC8378E,
            CPU_MPC8379 = ffi::UC_CPU_PPC_MPC8379,
            CPU_MPC8379E = ffi::UC_CPU_PPC_MPC8379E,
            CPU_E500_V10 = ffi::UC_CPU_PPC_E500_V10,
            CPU_E500_V20 = ffi::UC_CPU_PPC_E500_V20,
            CPU_E500V2_V10 = ffi::UC_CPU_PPC_E500V2_V10,
            CPU_E500V2_V20 = ffi::UC_CPU_PPC_E500V2_V20,
            CPU_E500V2_V21 = ffi::UC_CPU_PPC_E500V2_V21,
            CPU_E500V2_V22 = ffi::UC_CPU_PPC_E500V2_V22,
            CPU_E500V2_V30 = ffi::UC_CPU_PPC_E500V2_V30,
            CPU_E500MC = ffi::UC_CPU_PPC_E500MC,
            CPU_MPC8533_V10 = ffi::UC_CPU_PPC_MPC8533_V10,
            CPU_MPC8533_V11 = ffi::UC_CPU_PPC_MPC8533_V11,
            CPU_MPC8533E_V10 = ffi::UC_CPU_PPC_MPC8533E_V10,
            CPU_MPC8533E_V11 = ffi::UC_CPU_PPC_MPC8533E_V11,
            CPU_MPC8540_V10 = ffi::UC_CPU_PPC_MPC8540_V10,
            CPU_MPC8540_V20 = ffi::UC_CPU_PPC_MPC8540_V20,
            CPU_MPC8540_V21 = ffi::UC_CPU_PPC_MPC8540_V21,
            CPU_MPC8541_V10 = ffi::UC_CPU_PPC_MPC8541_V10,
            CPU_MPC8541_V11 = ffi::UC_CPU_PPC_MPC8541_V11,
            CPU_MPC8541E_V10 = ffi::UC_CPU_PPC_MPC8541E_V10,
            CPU_MPC8541E_V11 = ffi::UC_CPU_PPC_MPC8541E_V11,
            CPU_MPC8543_V10 = ffi::UC_CPU_PPC_MPC8543_V10,
            CPU_MPC8543_V11 = ffi::UC_CPU_PPC_MPC8543_V11,
            CPU_MPC8543_V20 = ffi::UC_CPU_PPC_MPC8543_V20,
            CPU_MPC8543_V21 = ffi::UC_CPU_PPC_MPC8543_V21,
            CPU_MPC8543E_V10 = ffi::UC_CPU_PPC_MPC8543E_V10,
            CPU_MPC8543E_V11 = ffi::UC_CPU_PPC_MPC8543E_V11,
            CPU_MPC8543E_V20 = ffi::UC_CPU_PPC_MPC8543E_V20,
            CPU_MPC8543E_V21 = ffi::UC_CPU_PPC_MPC8543E_V21,
            CPU_MPC8544_V10 = ffi::UC_CPU_PPC_MPC8544_V10,
            CPU_MPC8544_V11 = ffi::UC_CPU_PPC_MPC8544_V11,
            CPU_MPC8544E_V10 = ffi::UC_CPU_PPC_MPC8544E_V10,
            CPU_MPC8544E_V11 = ffi::UC_CPU_PPC_MPC8544E_V11,
            CPU_MPC8545_V20 = ffi::UC_CPU_PPC_MPC8545_V20,
            CPU_MPC8545_V21 = ffi::UC_CPU_PPC_MPC8545_V21,
            CPU_MPC8545E_V20 = ffi::UC_CPU_PPC_MPC8545E_V20,
            CPU_MPC8545E_V21 = ffi::UC_CPU_PPC_MPC8545E_V21,
            CPU_MPC8547E_V20 = ffi::UC_CPU_PPC_MPC8547E_V20,
            CPU_MPC8547E_V21 = ffi::UC_CPU_PPC_MPC8547E_V21,
            CPU_MPC8548_V10 = ffi::UC_CPU_PPC_MPC8548_V10,
            CPU_MPC8548_V11 = ffi::UC_CPU_PPC_MPC8548_V11,
            CPU_MPC8548_V20 = ffi::UC_CPU_PPC_MPC8548_V20,
            CPU_MPC8548_V21 = ffi::UC_CPU_PPC_MPC8548_V21,
            CPU_MPC8548E_V10 = ffi::UC_CPU_PPC_MPC8548E_V10,
            CPU_MPC8548E_V11 = ffi::UC_CPU_PPC_MPC8548E_V11,
            CPU_MPC8548E_V20 = ffi::UC_CPU_PPC_MPC8548E_V20,
            CPU_MPC8548E_V21 = ffi::UC_CPU_PPC_MPC8548E_V21,
            CPU_MPC8555_V10 = ffi::UC_CPU_PPC_MPC8555_V10,
            CPU_MPC8555_V11 = ffi::UC_CPU_PPC_MPC8555_V11,
            CPU_MPC8555E_V10 = ffi::UC_CPU_PPC_MPC8555E_V10,
            CPU_MPC8555E_V11 = ffi::UC_CPU_PPC_MPC8555E_V11,
            CPU_MPC8560_V10 = ffi::UC_CPU_PPC_MPC8560_V10,
            CPU_MPC8560_V20 = ffi::UC_CPU_PPC_MPC8560_V20,
            CPU_MPC8560_V21 = ffi::UC_CPU_PPC_MPC8560_V21,
            CPU_MPC8567 = ffi::UC_CPU_PPC_MPC8567,
            CPU_MPC8567E = ffi::UC_CPU_PPC_MPC8567E,
            CPU_MPC8568 = ffi::UC_CPU_PPC_MPC8568,
            CPU_MPC8568E = ffi::UC_CPU_PPC_MPC8568E,
            CPU_MPC8572 = ffi::UC_CPU_PPC_MPC8572,
            CPU_MPC8572E = ffi::UC_CPU_PPC_MPC8572E,
            CPU_E600 = ffi::UC_CPU_PPC_E600,
            CPU_MPC8610 = ffi::UC_CPU_PPC_MPC8610,
            CPU_MPC8641 = ffi::UC_CPU_PPC_MPC8641,
            CPU_MPC8641D = ffi::UC_CPU_PPC_MPC8641D,
            CPU_601_V0 = ffi::UC_CPU_PPC_601_V0,
            CPU_601_V1 = ffi::UC_CPU_PPC_601_V1,
            CPU_601_V2 = ffi::UC_CPU_PPC_601_V2,
            CPU_602 = ffi::UC_CPU_PPC_602,
            CPU_603 = ffi::UC_CPU_PPC_603,
            CPU_603E_V1_1 = ffi::UC_CPU_PPC_603E_V1_1,
            CPU_603E_V1_2 = ffi::UC_CPU_PPC_603E_V1_2,
            CPU_603E_V1_3 = ffi::UC_CPU_PPC_603E_V1_3,
            CPU_603E_V1_4 = ffi::UC_CPU_PPC_603E_V1_4,
            CPU_603E_V2_2 = ffi::UC_CPU_PPC_603E_V2_2,
            CPU_603E_V3 = ffi::UC_CPU_PPC_603E_V3,
            CPU_603E_V4 = ffi::UC_CPU_PPC_603E_V4,
            CPU_603E_V4_1 = ffi::UC_CPU_PPC_603E_V4_1,
            CPU_603E7 = ffi::UC_CPU_PPC_603E7,
            CPU_603E7T = ffi::UC_CPU_PPC_603E7T,
            CPU_603E7V = ffi::UC_CPU_PPC_603E7V,
            CPU_603E7V1 = ffi::UC_CPU_PPC_603E7V1,
            CPU_603E7V2 = ffi::UC_CPU_PPC_603E7V2,
            CPU_603P = ffi::UC_CPU_PPC_603P,
            CPU_604 = ffi::UC_CPU_PPC_604,
            CPU_604E_V1_0 = ffi::UC_CPU_PPC_604E_V1_0,
            CPU_604E_V2_2 = ffi::UC_CPU_PPC_604E_V2_2,
            CPU_604E_V2_4 = ffi::UC_CPU_PPC_604E_V2_4,
            CPU_604R = ffi::UC_CPU_PPC_604R,
            CPU_740_V1_0 = ffi::UC_CPU_PPC_740_V1_0,
            CPU_750_V1_0 = ffi::UC_CPU_PPC_750_V1_0,
            CPU_740_V2_0 = ffi::UC_CPU_PPC_740_V2_0,
            CPU_750_V2_0 = ffi::UC_CPU_PPC_750_V2_0,
            CPU_740_V2_1 = ffi::UC_CPU_PPC_740_V2_1,
            CPU_750_V2_1 = ffi::UC_CPU_PPC_750_V2_1,
            CPU_740_V2_2 = ffi::UC_CPU_PPC_740_V2_2,
            CPU_750_V2_2 = ffi::UC_CPU_PPC_750_V2_2,
            CPU_740_V3_0 = ffi::UC_CPU_PPC_740_V3_0,
            CPU_750_V3_0 = ffi::UC_CPU_PPC_750_V3_0,
            CPU_740_V3_1 = ffi::UC_CPU_PPC_740_V3_1,
            CPU_750_V3_1 = ffi::UC_CPU_PPC_750_V3_1,
            CPU_740E = ffi::UC_CPU_PPC_740E,
            CPU_750E = ffi::UC_CPU_PPC_750E,
            CPU_740P = ffi::UC_CPU_PPC_740P,
            CPU_750P = ffi::UC_CPU_PPC_750P,
            CPU_750CL_V1_0 = ffi::UC_CPU_PPC_750CL_V1_0,
            CPU_750CL_V2_0 = ffi::UC_CPU_PPC_750CL_V2_0,
            CPU_750CX_V1_0 = ffi::UC_CPU_PPC_750CX_V1_0,
            CPU_750CX_V2_0 = ffi::UC_CPU_PPC_750CX_V2_0,
            CPU_750CX_V2_1 = ffi::UC_CPU_PPC_750CX_V2_1,
            CPU_750CX_V2_2 = ffi::UC_CPU_PPC_750CX_V2_2,
            CPU_750CXE_V2_1 = ffi::UC_CPU_PPC_750CXE_V2_1,
            CPU_750CXE_V2_2 = ffi::UC_CPU_PPC_750CXE_V2_2,
            CPU_750CXE_V2_3 = ffi::UC_CPU_PPC_750CXE_V2_3,
            CPU_750CXE_V2_4 = ffi::UC_CPU_PPC_750CXE_V2_4,
            CPU_750CXE_V2_4B = ffi::UC_CPU_PPC_750CXE_V2_4B,
            CPU_750CXE_V3_0 = ffi::UC_CPU_PPC_750CXE_V3_0,
            CPU_750CXE_V3_1 = ffi::UC_CPU_PPC_750CXE_V3_1,
            CPU_750CXE_V3_1B = ffi::UC_CPU_PPC_750CXE_V3_1B,
            CPU_750CXR = ffi::UC_CPU_PPC_750CXR,
            CPU_750FL = ffi::UC_CPU_PPC_750FL,
            CPU_750FX_V1_0 = ffi::UC_CPU_PPC_750FX_V1_0,
            CPU_750FX_V2_0 = ffi::UC_CPU_PPC_750FX_V2_0,
            CPU_750FX_V2_1 = ffi::UC_CPU_PPC_750FX_V2_1,
            CPU_750FX_V2_2 = ffi::UC_CPU_PPC_750FX_V2_2,
            CPU_750FX_V2_3 = ffi::UC_CPU_PPC_750FX_V2_3,
            CPU_750GL = ffi::UC_CPU_PPC_750GL,
            CPU_750GX_V1_0 = ffi::UC_CPU_PPC_750GX_V1_0,
            CPU_750GX_V1_1 = ffi::UC_CPU_PPC_750GX_V1_1,
            CPU_750GX_V1_2 = ffi::UC_CPU_PPC_750GX_V1_2,
            CPU_750L_V2_0 = ffi::UC_CPU_PPC_750L_V2_0,
            CPU_750L_V2_1 = ffi::UC_CPU_PPC_750L_V2_1,
            CPU_750L_V2_2 = ffi::UC_CPU_PPC_750L_V2_2,
            CPU_750L_V3_0 = ffi::UC_CPU_PPC_750L_V3_0,
            CPU_750L_V3_2 = ffi::UC_CPU_PPC_750L_V3_2,
            CPU_745_V1_0 = ffi::UC_CPU_PPC_745_V1_0,
            CPU_755_V1_0 = ffi::UC_CPU_PPC_755_V1_0,
            CPU_745_V1_1 = ffi::UC_CPU_PPC_745_V1_1,
            CPU_755_V1_1 = ffi::UC_CPU_PPC_755_V1_1,
            CPU_745_V2_0 = ffi::UC_CPU_PPC_745_V2_0,
            CPU_755_V2_0 = ffi::UC_CPU_PPC_755_V2_0,
            CPU_745_V2_1 = ffi::UC_CPU_PPC_745_V2_1,
            CPU_755_V2_1 = ffi::UC_CPU_PPC_755_V2_1,
            CPU_745_V2_2 = ffi::UC_CPU_PPC_745_V2_2,
            CPU_755_V2_2 = ffi::UC_CPU_PPC_755_V2_2,
            CPU_745_V2_3 = ffi::UC_CPU_PPC_745_V2_3,
            CPU_755_V2_3 = ffi::UC_CPU_PPC_755_V2_3,
            CPU_745_V2_4 = ffi::UC_CPU_PPC_745_V2_4,
            CPU_755_V2_4 = ffi::UC_CPU_PPC_755_V2_4,
            CPU_745_V2_5 = ffi::UC_CPU_PPC_745_V2_5,
            CPU_755_V2_5 = ffi::UC_CPU_PPC_755_V2_5,
            CPU_745_V2_6 = ffi::UC_CPU_PPC_745_V2_6,
            CPU_755_V2_6 = ffi::UC_CPU_PPC_755_V2_6,
            CPU_745_V2_7 = ffi::UC_CPU_PPC_745_V2_7,
            CPU_755_V2_7 = ffi::UC_CPU_PPC_755_V2_7,
            CPU_745_V2_8 = ffi::UC_CPU_PPC_745_V2_8,
            CPU_755_V2_8 = ffi::UC_CPU_PPC_755_V2_8,
            CPU_7400_V1_0 = ffi::UC_CPU_PPC_7400_V1_0,
            CPU_7400_V1_1 = ffi::UC_CPU_PPC_7400_V1_1,
            CPU_7400_V2_0 = ffi::UC_CPU_PPC_7400_V2_0,
            CPU_7400_V2_1 = ffi::UC_CPU_PPC_7400_V2_1,
            CPU_7400_V2_2 = ffi::UC_CPU_PPC_7400_V2_2,
            CPU_7400_V2_6 = ffi::UC_CPU_PPC_7400_V2_6,
            CPU_7400_V2_7 = ffi::UC_CPU_PPC_7400_V2_7,
            CPU_7400_V2_8 = ffi::UC_CPU_PPC_7400_V2_8,
            CPU_7400_V2_9 = ffi::UC_CPU_PPC_7400_V2_9,
            CPU_7410_V1_0 = ffi::UC_CPU_PPC_7410_V1_0,
            CPU_7410_V1_1 = ffi::UC_CPU_PPC_7410_V1_1,
            CPU_7410_V1_2 = ffi::UC_CPU_PPC_7410_V1_2,
            CPU_7410_V1_3 = ffi::UC_CPU_PPC_7410_V1_3,
            CPU_7410_V1_4 = ffi::UC_CPU_PPC_7410_V1_4,
            CPU_7448_V1_0 = ffi::UC_CPU_PPC_7448_V1_0,
            CPU_7448_V1_1 = ffi::UC_CPU_PPC_7448_V1_1,
            CPU_7448_V2_0 = ffi::UC_CPU_PPC_7448_V2_0,
            CPU_7448_V2_1 = ffi::UC_CPU_PPC_7448_V2_1,
            CPU_7450_V1_0 = ffi::UC_CPU_PPC_7450_V1_0,
            CPU_7450_V1_1 = ffi::UC_CPU_PPC_7450_V1_1,
            CPU_7450_V1_2 = ffi::UC_CPU_PPC_7450_V1_2,
            CPU_7450_V2_0 = ffi::UC_CPU_PPC_7450_V2_0,
            CPU_7450_V2_1 = ffi::UC_CPU_PPC_7450_V2_1,
            CPU_7441_V2_1 = ffi::UC_CPU_PPC_7441_V2_1,
            CPU_7441_V2_3 = ffi::UC_CPU_PPC_7441_V2_3,
            CPU_7451_V2_3 = ffi::UC_CPU_PPC_7451_V2_3,
            CPU_7441_V2_10 = ffi::UC_CPU_PPC_7441_V2_10,
            CPU_7451_V2_10 = ffi::UC_CPU_PPC_7451_V2_10,
            CPU_7445_V1_0 = ffi::UC_CPU_PPC_7445_V1_0,
            CPU_7455_V1_0 = ffi::UC_CPU_PPC_7455_V1_0,
            CPU_7445_V2_1 = ffi::UC_CPU_PPC_7445_V2_1,
            CPU_7455_V2_1 = ffi::UC_CPU_PPC_7455_V2_1,
            CPU_7445_V3_2 = ffi::UC_CPU_PPC_7445_V3_2,
            CPU_7455_V3_2 = ffi::UC_CPU_PPC_7455_V3_2,
            CPU_7445_V3_3 = ffi::UC_CPU_PPC_7445_V3_3,
            CPU_7455_V3_3 = ffi::UC_CPU_PPC_7455_V3_3,
            CPU_7445_V3_4 = ffi::UC_CPU_PPC_7445_V3_4,
            CPU_7455_V3_4 = ffi::UC_CPU_PPC_7455_V3_4,
            CPU_7447_V1_0 = ffi::UC_CPU_PPC_7447_V1_0,
            CPU_7457_V1_0 = ffi::UC_CPU_PPC_7457_V1_0,
            CPU_7447_V1_1 = ffi::UC_CPU_PPC_7447_V1_1,
            CPU_7457_V1_1 = ffi::UC_CPU_PPC_7457_V1_1,
            CPU_7457_V1_2 = ffi::UC_CPU_PPC_7457_V1_2,
            CPU_7447A_V1_0 = ffi::UC_CPU_PPC_7447A_V1_0,
            CPU_7457A_V1_0 = ffi::UC_CPU_PPC_7457A_V1_0,
            CPU_7447A_V1_1 = ffi::UC_CPU_PPC_7447A_V1_1,
            CPU_7457A_V1_1 = ffi::UC_CPU_PPC_7457A_V1_1,
            CPU_7447A_V1_2 = ffi::UC_CPU_PPC_7447A_V1_2,
            CPU_7457A_V1_2 = ffi::UC_CPU_PPC_7457A_V1_2,
        };
    };
    //! @brief Implement Architecture interface for PPC32.
    UNICORN_HPP_IMPL_ARCH(PPC32);

    //! @brief PPC64 architecture.
    struct PPC64 : PPC {
        //! @brief Mode flags.
        enum Mode : unsigned {
            MODE_INIT = ffi::UC_MODE_PPC64,        ///< Implicit mode flags for engine creation.
            MODE_LE = ffi::UC_MODE_LITTLE_ENDIAN,  ///< Little-endian mode (default mode).
            MODE_BE = ffi::UC_MODE_BIG_ENDIAN,     ///< Big-endian mode.
            MODE_32 = ffi::UC_MODE_PPC32,          ///< 32bit mode.
            MODE_64 = ffi::UC_MODE_PPC64,          ///< 64bit mode.
        };

        //! @brief CPU Type.
        enum CPU : unsigned {
            CPU_DEFAULT = (unsigned)-1,
            CPU_E5500 = ffi::UC_CPU_PPC_E5500,
            CPU_E6500 = ffi::UC_CPU_PPC_E6500,
            CPU_970_V2_2 = ffi::UC_CPU_PPC_970_V2_2,
            CPU_970FX_V1_0 = ffi::UC_CPU_PPC_970FX_V1_0,
            CPU_970FX_V2_0 = ffi::UC_CPU_PPC_970FX_V2_0,
            CPU_970FX_V2_1 = ffi::UC_CPU_PPC_970FX_V2_1,
            CPU_970FX_V3_0 = ffi::UC_CPU_PPC_970FX_V3_0,
            CPU_970FX_V3_1 = ffi::UC_CPU_PPC_970FX_V3_1,
            CPU_970MP_V1_0 = ffi::UC_CPU_PPC_970MP_V1_0,
            CPU_970MP_V1_1 = ffi::UC_CPU_PPC_970MP_V1_1,
            CPU_POWER5_V2_1 = ffi::UC_CPU_PPC_POWER5_V2_1,
            CPU_POWER7_V2_3 = ffi::UC_CPU_PPC_POWER7_V2_3,
            CPU_POWER7_V2_1 = ffi::UC_CPU_PPC_POWER7_V2_1,
            CPU_POWER8E_V2_1 = ffi::UC_CPU_PPC_POWER8E_V2_1,
            CPU_POWER8_V2_0 = ffi::UC_CPU_PPC_POWER8_V2_0,
            CPU_POWER8NVL_V1_0 = ffi::UC_CPU_PPC_POWER8NVL_V1_0,
            CPU_POWER9_V1_0 = ffi::UC_CPU_PPC_POWER9_V1_0,
            CPU_POWER9_V2_0 = ffi::UC_CPU_PPC_POWER9_V2_0,
            CPU_POWER10_V1_0 = ffi::UC_CPU_PPC_POWER10_V1_0,
        };
    };
    //! @brief Implement Architecture interface for PPC64.
    UNICORN_HPP_IMPL_ARCH(PPC64);
#endif

#ifndef UNICORN_HPP_NO_RISCV
    //! @brief Common definitions for RISCV32 & RISCV64 architecure.
    struct RISCV {
        //! @brief Raw unicorn architecture ID.
        static constexpr inline auto ARCH = ffi::UC_ARCH_RISCV;

        //! @brief RISC-V registers API.
        union RegsAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_PC> pc;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X0> x0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X1> x1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X2> x2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X3> x3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X4> x4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X5> x5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X6> x6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X7> x7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X8> x8;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X9> x9;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X10> x10;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X11> x11;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X12> x12;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X13> x13;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X14> x14;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X15> x15;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X16> x16;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X17> x17;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X18> x18;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X19> x19;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X20> x20;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X21> x21;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X22> x22;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X23> x23;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X24> x24;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X25> x25;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X26> x26;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X27> x27;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X28> x28;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X29> x29;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X30> x30;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_X31> x31;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F0> f0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F1> f1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F2> f2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F3> f3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F4> f4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F5> f5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F6> f6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F7> f7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F8> f8;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F9> f9;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F10> f10;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F11> f11;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F12> f12;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F13> f13;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F14> f14;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F15> f15;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F16> f16;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F17> f17;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F18> f18;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F19> f19;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F20> f20;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F21> f21;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F22> f22;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F23> f23;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F24> f24;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F25> f25;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F26> f26;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F27> f27;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F28> f28;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F29> f29;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F30> f30;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_F31> f31;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_ZERO> zero;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_RA> ra;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_SP> sp;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_GP> gp;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_TP> tp;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_T0> t0;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_T1> t1;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_T2> t2;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_S0> s0;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FP> fp;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_S1> s1;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_A0> a0;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_A1> a1;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_A2> a2;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_A3> a3;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_A4> a4;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_A5> a5;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_A6> a6;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_A7> a7;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_S2> s2;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_S3> s3;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_S4> s4;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_S5> s5;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_S6> s6;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_S7> s7;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_S8> s8;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_S9> s9;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_S10> s10;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_S11> s11;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_T3> t3;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_T4> t4;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_T5> t5;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_T6> t6;      ///< reg.

            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FT0> ft0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FT1> ft1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FT2> ft2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FT3> ft3;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FT4> ft4;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FT5> ft5;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FT6> ft6;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FT7> ft7;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FS0> fs0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FS1> fs1;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FA0> fa0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FA1> fa1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FA2> fa2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FA3> fa3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FA4> fa4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FA5> fa5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FA6> fa6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FA7> fa7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FS2> fs2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FS3> fs3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FS4> fs4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FS5> fs5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FS6> fs6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FS7> fs7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FS8> fs8;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FS9> fs9;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FS10> fs10;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FS11> fs11;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FT8> ft8;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FT9> ft9;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FT10> ft10;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_RISCV_REG_FT11> ft11;  ///< reg.
        };
    };

    //! @brief RISCV32 architecture.
    struct RISCV32 : RISCV {
        //! @brief Mode flags.
        enum Mode : unsigned {
            MODE_INIT = ffi::UC_MODE_RISCV32,      ///< Implicit mode flags for engine creation.
            MODE_LE = ffi::UC_MODE_LITTLE_ENDIAN,  ///< Little-endian mode (default mode).
            MODE_32 = ffi::UC_MODE_RISCV32,        ///< 32bit mode.
        };

        //! @brief CPU Type.
        enum CPU : unsigned {
            CPU_DEFAULT = (unsigned)-1,
            CPU_ANY = ffi::UC_CPU_RISCV32_ANY,
            CPU_BASE32 = ffi::UC_CPU_RISCV32_BASE32,
            CPU_SIFIVE_E31 = ffi::UC_CPU_RISCV32_SIFIVE_E31,
            CPU_SIFIVE_U34 = ffi::UC_CPU_RISCV32_SIFIVE_U34,
        };
    };
    //! @brief Implement Architecture interface for RISCV32.
    UNICORN_HPP_IMPL_ARCH(RISCV32);

    //! @brief RISCV64 architecture.
    struct RISCV64 : RISCV {
        //! @brief Mode flags.
        enum Mode : unsigned {
            MODE_INIT = ffi::UC_MODE_RISCV64,      ///< Implicit mode flags for engine creation.
            MODE_LE = ffi::UC_MODE_LITTLE_ENDIAN,  ///< Little-endian mode (default mode).
            MODE_32 = ffi::UC_MODE_RISCV32,        ///< 32bit mode.
            MODE_64 = ffi::UC_MODE_RISCV64,        ///< 64bit mode.
        };

        //! @brief CPU Type.
        enum CPU : unsigned {
            CPU_DEFAULT = (unsigned)-1,
            CPU_ANY = ffi::UC_CPU_RISCV64_ANY,
            CPU_BASE64 = ffi::UC_CPU_RISCV64_BASE64,
            CPU_SIFIVE_E51 = ffi::UC_CPU_RISCV64_SIFIVE_E51,
            CPU_SIFIVE_U54 = ffi::UC_CPU_RISCV64_SIFIVE_U54,
        };
    };
    //! @brief Implement Architecture interface for RISCV64.
    UNICORN_HPP_IMPL_ARCH(RISCV64);
#endif

#ifndef UNICORN_HPP_NO_SPARC
    //! @brief Common definitions for SPARC32 & SPARC64 architecure.
    struct SPARC {
        //! @brief Raw unicorn architecture ID.
        static constexpr inline auto ARCH = ffi::UC_ARCH_SPARC;

        //! @brief SPARC registers API.
        union RegsAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            // pseudo register
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_PC> pc;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F0> f0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F1> f1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F2> f2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F3> f3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F4> f4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F5> f5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F6> f6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F7> f7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F8> f8;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F9> f9;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F10> f10;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F11> f11;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F12> f12;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F13> f13;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F14> f14;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F15> f15;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F16> f16;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F17> f17;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F18> f18;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F19> f19;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F20> f20;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F21> f21;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F22> f22;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F23> f23;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F24> f24;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F25> f25;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F26> f26;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F27> f27;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F28> f28;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F29> f29;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F30> f30;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F31> f31;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F32> f32;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F34> f34;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F36> f36;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F38> f38;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F40> f40;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F42> f42;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F44> f44;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F46> f46;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F48> f48;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F50> f50;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F52> f52;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F54> f54;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F56> f56;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F58> f58;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F60> f60;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_F62> f62;  ///< reg.

            // Floating condition codes
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_FCC0> fcc0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_FCC1> fcc1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_FCC2> fcc2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_FCC3> fcc3;  ///< reg.

            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_G0> g0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_G1> g1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_G2> g2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_G3> g3;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_G4> g4;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_G5> g5;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_G6> g6;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_G7> g7;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_I0> i0;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_I1> i1;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_I2> i2;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_I3> i3;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_I4> i4;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_I5> i5;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_FP> fp;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_I7> i7;  ///< reg.

            // Integer condition codes
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_ICC> icc;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_L0> l0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_L1> l1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_L2> l2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_L3> l3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_L4> l4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_L5> l5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_L6> l6;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_L7> l7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_O0> o0;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_O1> o1;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_O2> o2;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_O3> o3;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_O4> o4;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_O5> o5;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_SP> sp;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_O7> o7;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_Y> y;      ///< reg.

            // special register
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_XCC> xcc;  ///< reg.

            // extras
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_O6> o6;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_SPARC_REG_I6> i6;  ///< reg.
        };
    };

    //! @brief SPARC32 architecture.
    struct SPARC32 : SPARC {
        //! @brief Mode flags.
        enum Mode : unsigned {
            MODE_INIT = ffi::UC_MODE_SPARC32,      ///< Implicit mode flags for engine creation.
            MODE_LE = ffi::UC_MODE_LITTLE_ENDIAN,  ///< Little-endian mode (default mode).
            MODE_BE = ffi::UC_MODE_BIG_ENDIAN,     ///< Big-endian mode.
            MODE_32 = ffi::UC_MODE_SPARC32,        ///< 32bit mode.
        };

        //! @brief CPU Type.
        enum CPU : unsigned {
            CPU_DEFAULT = (unsigned)-1,
            CPU_FUJITSU_MB86904 = ffi::UC_CPU_SPARC32_FUJITSU_MB86904,
            CPU_FUJITSU_MB86907 = ffi::UC_CPU_SPARC32_FUJITSU_MB86907,
            CPU_TI_MICROSPARC_I = ffi::UC_CPU_SPARC32_TI_MICROSPARC_I,
            CPU_TI_MICROSPARC_II = ffi::UC_CPU_SPARC32_TI_MICROSPARC_II,
            CPU_TI_MICROSPARC_IIEP = ffi::UC_CPU_SPARC32_TI_MICROSPARC_IIEP,
            CPU_TI_SUPERSPARC_40 = ffi::UC_CPU_SPARC32_TI_SUPERSPARC_40,
            CPU_TI_SUPERSPARC_50 = ffi::UC_CPU_SPARC32_TI_SUPERSPARC_50,
            CPU_TI_SUPERSPARC_51 = ffi::UC_CPU_SPARC32_TI_SUPERSPARC_51,
            CPU_TI_SUPERSPARC_60 = ffi::UC_CPU_SPARC32_TI_SUPERSPARC_60,
            CPU_TI_SUPERSPARC_61 = ffi::UC_CPU_SPARC32_TI_SUPERSPARC_61,
            CPU_TI_SUPERSPARC_II = ffi::UC_CPU_SPARC32_TI_SUPERSPARC_II,
            CPU_LEON2 = ffi::UC_CPU_SPARC32_LEON2,
            CPU_LEON3 = ffi::UC_CPU_SPARC32_LEON3,
        };
    };
    //! @brief Implement Architecture interface for SPARC64.
    UNICORN_HPP_IMPL_ARCH(SPARC32);

    //! @brief SPARC64 architecture.
    struct SPARC64 : SPARC {
        //! @brief Mode flags.
        enum Mode : unsigned {
            MODE_INIT = ffi::UC_MODE_SPARC64,      ///< Implicit mode flags for engine creation.
            MODE_LE = ffi::UC_MODE_LITTLE_ENDIAN,  ///< Little-endian mode (default mode).
            MODE_BE = ffi::UC_MODE_BIG_ENDIAN,     ///< Big-endian mode.
            MODE_32 = ffi::UC_MODE_SPARC32,        ///< 32bit mode.
            MODE_64 = ffi::UC_MODE_SPARC64,        ///< 64bit mode.
        };

        //! @brief CPU Type.
        enum CPU : unsigned {
            CPU_DEFAULT = (unsigned)-1,
            CPU_FUJITSU = ffi::UC_CPU_SPARC64_FUJITSU,
            CPU_FUJITSU_III = ffi::UC_CPU_SPARC64_FUJITSU_III,
            CPU_FUJITSU_IV = ffi::UC_CPU_SPARC64_FUJITSU_IV,
            CPU_FUJITSU_V = ffi::UC_CPU_SPARC64_FUJITSU_V,
            CPU_TI_ULTRASPARC_I = ffi::UC_CPU_SPARC64_TI_ULTRASPARC_I,
            CPU_TI_ULTRASPARC_II = ffi::UC_CPU_SPARC64_TI_ULTRASPARC_II,
            CPU_TI_ULTRASPARC_III = ffi::UC_CPU_SPARC64_TI_ULTRASPARC_III,
            CPU_TI_ULTRASPARC_IIE = ffi::UC_CPU_SPARC64_TI_ULTRASPARC_IIE,
            CPU_SUN_ULTRASPARC_III = ffi::UC_CPU_SPARC64_SUN_ULTRASPARC_III,
            CPU_SUN_ULTRASPARC_III_CU = ffi::UC_CPU_SPARC64_SUN_ULTRASPARC_III_CU,
            CPU_SUN_ULTRASPARC_IIII = ffi::UC_CPU_SPARC64_SUN_ULTRASPARC_IIII,
            CPU_SUN_ULTRASPARC_IV = ffi::UC_CPU_SPARC64_SUN_ULTRASPARC_IV,
            CPU_SUN_ULTRASPARC_IV_PLUS = ffi::UC_CPU_SPARC64_SUN_ULTRASPARC_IV_PLUS,
            CPU_SUN_ULTRASPARC_IIII_PLUS = ffi::UC_CPU_SPARC64_SUN_ULTRASPARC_IIII_PLUS,
            CPU_SUN_ULTRASPARC_T1 = ffi::UC_CPU_SPARC64_SUN_ULTRASPARC_T1,
            CPU_SUN_ULTRASPARC_T2 = ffi::UC_CPU_SPARC64_SUN_ULTRASPARC_T2,
            CPU_NEC_ULTRASPARC_I = ffi::UC_CPU_SPARC64_NEC_ULTRASPARC_I,
        };
    };
    //! @brief Implement Architecture interface for SPARC64.
    UNICORN_HPP_IMPL_ARCH(SPARC64);
#endif

#ifndef UNICORN_HPP_NO_X86
    //! @brief X86(i386, i486, i585, i686, x86_64, x64) architecture.
    struct X86 {
        //! @brief Raw unicorn architecture ID.
        static constexpr inline auto ARCH = ffi::UC_ARCH_X86;

        //! @brief Mode flags.
        enum Mode : unsigned {
            MODE_INIT = 0,                         ///< Implicit mode flags for engine creation.
            MODE_LE = ffi::UC_MODE_LITTLE_ENDIAN,  ///< Little-endian mode (default mode).
            MODE_16 = ffi::UC_MODE_16,             ///< 16bit mode.
            MODE_32 = ffi::UC_MODE_32,             ///< 32bit mode.
            MODE_64 = ffi::UC_MODE_64,             ///< 64bit mode.
        };

        //! @brief CPU Type.
        enum CPU : unsigned {
            CPU_DEFAULT = (unsigned)-1,
            CPU_QEMU64 = ffi::UC_CPU_X86_QEMU64,
            CPU_PHENOM = ffi::UC_CPU_X86_PHENOM,
            CPU_CORE2DUO = ffi::UC_CPU_X86_CORE2DUO,
            CPU_KVM64 = ffi::UC_CPU_X86_KVM64,
            CPU_QEMU32 = ffi::UC_CPU_X86_QEMU32,
            CPU_KVM32 = ffi::UC_CPU_X86_KVM32,
            CPU_COREDUO = ffi::UC_CPU_X86_COREDUO,
            CPU_486 = ffi::UC_CPU_X86_486,
            CPU_PENTIUM = ffi::UC_CPU_X86_PENTIUM,
            CPU_PENTIUM2 = ffi::UC_CPU_X86_PENTIUM2,
            CPU_PENTIUM3 = ffi::UC_CPU_X86_PENTIUM3,
            CPU_ATHLON = ffi::UC_CPU_X86_ATHLON,
            CPU_N270 = ffi::UC_CPU_X86_N270,
            CPU_CONROE = ffi::UC_CPU_X86_CONROE,
            CPU_PENRYN = ffi::UC_CPU_X86_PENRYN,
            CPU_NEHALEM = ffi::UC_CPU_X86_NEHALEM,
            CPU_WESTMERE = ffi::UC_CPU_X86_WESTMERE,
            CPU_SANDYBRIDGE = ffi::UC_CPU_X86_SANDYBRIDGE,
            CPU_IVYBRIDGE = ffi::UC_CPU_X86_IVYBRIDGE,
            CPU_HASWELL = ffi::UC_CPU_X86_HASWELL,
            CPU_BROADWELL = ffi::UC_CPU_X86_BROADWELL,
            CPU_SKYLAKE_CLIENT = ffi::UC_CPU_X86_SKYLAKE_CLIENT,
            CPU_SKYLAKE_SERVER = ffi::UC_CPU_X86_SKYLAKE_SERVER,
            CPU_CASCADELAKE_SERVER = ffi::UC_CPU_X86_CASCADELAKE_SERVER,
            CPU_COOPERLAKE = ffi::UC_CPU_X86_COOPERLAKE,
            CPU_ICELAKE_CLIENT = ffi::UC_CPU_X86_ICELAKE_CLIENT,
            CPU_ICELAKE_SERVER = ffi::UC_CPU_X86_ICELAKE_SERVER,
            CPU_DENVERTON = ffi::UC_CPU_X86_DENVERTON,
            CPU_SNOWRIDGE = ffi::UC_CPU_X86_SNOWRIDGE,
            CPU_KNIGHTSMILL = ffi::UC_CPU_X86_KNIGHTSMILL,
            CPU_OPTERON_G1 = ffi::UC_CPU_X86_OPTERON_G1,
            CPU_OPTERON_G2 = ffi::UC_CPU_X86_OPTERON_G2,
            CPU_OPTERON_G3 = ffi::UC_CPU_X86_OPTERON_G3,
            CPU_OPTERON_G4 = ffi::UC_CPU_X86_OPTERON_G4,
            CPU_OPTERON_G5 = ffi::UC_CPU_X86_OPTERON_G5,
            CPU_EPYC = ffi::UC_CPU_X86_EPYC,
            CPU_DHYANA = ffi::UC_CPU_X86_DHYANA,
            CPU_EPYC_ROME = ffi::UC_CPU_X86_EPYC_ROME,
        };

        //! @brief 80bit floating point numbers (long double in GCC).
        struct F80 {
            //! @brief Mantisa of 80bit floating point number.
            std::uint64_t mantisa;

            //! @brief Exponent and sign flag of 80bit floating point number.
            std::uint16_t exponent;

            //! @brief Check if two F80 are bitwise equal.
            bool operator==(X86::F80 const& rhs) const noexcept {
                return std::tie(mantisa, exponent) == std::tie(rhs.mantisa, rhs.exponent);
            }

            //! @brief Check if two F80 are not bitwise equal.
            bool operator!=(X86::F80 const& rhs) const noexcept { return !operator==(rhs); }
        };

        //! @brief Memory-Management Register for instructions IDTR, GDTR, LDTR, TR.
        struct MMR {
            //! @brief Segment selector.
            std::uint16_t selector;
            //! @brief Segment base.
            std::uint64_t base;
            //! @brief Segment limit.
            std::uint32_t limit;
            //! @brief Segment flags.
            std::uint32_t flags;

            //! @brief Check if two MMR are bitwise equal.
            bool operator==(X86::MMR const& rhs) const noexcept {
                return std::tie(selector, base, limit, flags) == std::tie(rhs.selector, rhs.base, rhs.limit, rhs.flags);
            }

            //! @brief Check if two MMR are not bitwise equal.
            bool operator!=(X86::MMR const& rhs) const noexcept { return !operator==(rhs); }
        };
        static_assert(utility::is_layout_compatible_v<MMR, ffi::uc_x86_mmr>);

        //! @brief Model-Specific Register API.
        struct MSRegAPI {
            //! @brief Internal handle to unicorn engine.
            ffi::uc_engine* _uc;

            //! @brief Read register.
            std::uint64_t read(std::uint32_t id) const noexcept {
                ffi::uc_x86_msr msr = {id};
                ffi::uc_reg_read(_uc, ffi::UC_X86_REG_MSR, &msr);
                return msr.value;
            }

            //! @brief Write register value.
            //!
            //! @param value to write from
            void write(std::uint32_t id, std::uint64_t value) const noexcept {
                ffi::uc_x86_msr msr = {id, value};
                ffi::uc_reg_write(_uc, ffi::UC_X86_REG_MSR, &msr);
            }

            //! @brief Register reference type return by operator*
            struct Ref {
                //! @brief Internal handle to unicorn engine.
                ffi::uc_engine* const _uc;

                //! @brief Id of model specific register.
                std::uint32_t const _id;

                //! @brief Automatically converts to underlying type.
                operator std::uint64_t() const noexcept {
                    ffi::uc_x86_msr msr = {_id};
                    ffi::uc_reg_read(_uc, ffi::UC_X86_REG_MSR, &msr);
                    return msr.value;
                }

                //! @brief Can be assigned from anything that converts into T.
                //!
                //! @param value to write
                std::uint64_t operator=(std::uint64_t value) const noexcept {
                    ffi::uc_x86_msr msr = {_id, value};
                    ffi::uc_reg_write(_uc, ffi::UC_X86_REG_MSR, &msr);
                    return value;
                }

                //! @brief Assign register to itself is meaningles.
                void operator=(Ref&& value) = delete;
            };

            //! @brief Access model specific register from operator[].
            Ref operator[](std::uint32_t id) const noexcept { return Ref{_uc, id}; }
        };

        //! @brief X86 registers API.
        union RegsAPI {
            //! @brief Internal pointer to unicorn engine.
            ffi::uc_engine* _uc;

            mem::Register<std::uint8_t, ffi::UC_X86_REG_AH> ah;           ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_AL> al;           ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_AX> ax;          ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_BH> bh;           ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_BL> bl;           ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_BP> bp;          ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_BPL> bpl;         ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_BX> bx;          ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_CH> ch;           ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_CL> cl;           ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_CS> cs;          ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_CX> cx;          ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_DH> dh;           ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_DI> di;          ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_DIL> dil;         ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_DL> dl;           ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_DS> ds;          ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_DX> dx;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_EAX> eax;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_EBP> ebp;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_EBX> ebx;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_ECX> ecx;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_EDI> edi;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_EDX> edx;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_EFLAGS> eflags;  ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_EIP> eip;        ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_ES> es;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_ESI> esi;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_ESP> esp;        ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_FPSW> fpsw;      ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_FS> fs;          ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_GS> gs;          ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_IP> ip;          ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_RAX> rax;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_RBP> rbp;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_RBX> rbx;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_RCX> rcx;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_RDI> rdi;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_RDX> rdx;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_RIP> rip;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_RSI> rsi;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_RSP> rsp;        ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_SI> si;          ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_SIL> sil;         ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_SP> sp;          ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_SPL> spl;         ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_SS> ss;          ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_CR0> cr0;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_CR1> cr1;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_CR2> cr2;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_CR3> cr3;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_CR4> cr4;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_CR8> cr8;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_DR0> dr0;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_DR1> dr1;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_DR2> dr2;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_DR3> dr3;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_DR4> dr4;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_DR5> dr5;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_DR6> dr6;        ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_DR7> dr7;        ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_FP0> fp0;             ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_FP1> fp1;             ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_FP2> fp2;             ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_FP3> fp3;             ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_FP4> fp4;             ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_FP5> fp5;             ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_FP6> fp6;             ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_FP7> fp7;             ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_K0> k0; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_K1> k1; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_K2> k2; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_K3> k3; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_K4> k4; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_K5> k5; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_K6> k6; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_K7> k7; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_MM0> mm0; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_MM1> mm1; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_MM2> mm2; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_MM3> mm3; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_MM4> mm4; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_MM5> mm5; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_MM6> mm6; ///< reg.
            // mem::Register<void, ffi::UC_X86_REG_MM7> mm7; ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_R8> r8;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_R9> r9;        ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_R10> r10;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_R11> r11;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_R12> r12;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_R13> r13;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_R14> r14;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_R15> r15;      ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_ST0> st0;           ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_ST1> st1;           ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_ST2> st2;           ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_ST3> st3;           ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_ST4> st4;           ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_ST5> st5;           ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_ST6> st6;           ///< reg.
            mem::Register<X86::F80, ffi::UC_X86_REG_ST7> st7;           ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM0> xmm0;        ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM1> xmm1;        ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM2> xmm2;        ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM3> xmm3;        ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM4> xmm4;        ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM5> xmm5;        ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM6> xmm6;        ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM7> xmm7;        ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM8> xmm8;        ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM9> xmm9;        ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM10> xmm10;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM11> xmm11;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM12> xmm12;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM13> xmm13;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM14> xmm14;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM15> xmm15;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM16> xmm16;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM17> xmm17;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM18> xmm18;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM19> xmm19;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM20> xmm20;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM21> xmm21;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM22> xmm22;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM23> xmm23;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM24> xmm24;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM25> xmm25;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM26> xmm26;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM27> xmm27;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM28> xmm28;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM29> xmm29;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM30> xmm30;      ///< reg.
            mem::Register<mem::U128, ffi::UC_X86_REG_XMM31> xmm31;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM0> ymm0;        ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM1> ymm1;        ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM2> ymm2;        ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM3> ymm3;        ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM4> ymm4;        ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM5> ymm5;        ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM6> ymm6;        ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM7> ymm7;        ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM8> ymm8;        ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM9> ymm9;        ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM10> ymm10;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM11> ymm11;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM12> ymm12;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM13> ymm13;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM14> ymm14;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM15> ymm15;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM16> ymm16;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM17> ymm17;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM18> ymm18;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM19> ymm19;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM20> ymm20;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM21> ymm21;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM22> ymm22;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM23> ymm23;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM24> ymm24;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM25> ymm25;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM26> ymm26;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM27> ymm27;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM28> ymm28;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM29> ymm29;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM30> ymm30;      ///< reg.
            mem::Register<mem::U256, ffi::UC_X86_REG_YMM31> ymm31;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM0> zmm0;        ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM1> zmm1;        ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM2> zmm2;        ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM3> zmm3;        ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM4> zmm4;        ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM5> zmm5;        ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM6> zmm6;        ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM7> zmm7;        ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM8> zmm8;        ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM9> zmm9;        ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM10> zmm10;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM11> zmm11;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM12> zmm12;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM13> zmm13;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM14> zmm14;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM15> zmm15;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM16> zmm16;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM17> zmm17;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM18> zmm18;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM19> zmm19;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM20> zmm20;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM21> zmm21;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM22> zmm22;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM23> zmm23;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM24> zmm24;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM25> zmm25;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM26> zmm26;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM27> zmm27;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM28> zmm28;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM29> zmm29;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM30> zmm30;      ///< reg.
            mem::Register<mem::U512, ffi::UC_X86_REG_ZMM31> zmm31;      ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_R8B> r8b;       ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_R9B> r9b;       ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_R10B> r10b;     ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_R11B> r11b;     ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_R12B> r12b;     ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_R13B> r13b;     ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_R14B> r14b;     ///< reg.
            mem::Register<std::uint8_t, ffi::UC_X86_REG_R15B> r15b;     ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_R8D> r8d;      ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_R9D> r9d;      ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_R10D> r10d;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_R11D> r11d;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_R12D> r12d;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_R13D> r13d;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_R14D> r14d;    ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_R15D> r15d;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_R8W> r8w;      ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_R9W> r9w;      ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_R10W> r10w;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_R11W> r11w;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_R12W> r12w;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_R13W> r13w;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_R14W> r14w;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_R15W> r15w;    ///< reg.
            mem::Register<X86::MMR, ffi::UC_X86_REG_IDTR> idtr;         ///< reg.
            mem::Register<X86::MMR, ffi::UC_X86_REG_GDTR> gdtr;         ///< reg.
            mem::Register<X86::MMR, ffi::UC_X86_REG_LDTR> ldtr;         ///< reg.
            mem::Register<X86::MMR, ffi::UC_X86_REG_TR> tr;             ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_FPCW> fpcw;    ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_FPTAG> fptag;  ///< reg.
            MSRegAPI msr;                                               ///< reg.
            mem::Register<std::uint32_t, ffi::UC_X86_REG_MXCSR> mxcsr;  ///< reg.
            // Base regs for x86_64
            mem::Register<std::uint64_t, ffi::UC_X86_REG_FS_BASE> fs_base;  ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_GS_BASE> gs_base;  ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_FLAGS> flags;      ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_RFLAGS> rflags;    ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_FIP> fip;          ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_FCS> fcs;          ///< reg.
            mem::Register<std::uint64_t, ffi::UC_X86_REG_FDP> fdp;          ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_FDS> fds;          ///< reg.
            mem::Register<std::uint16_t, ffi::UC_X86_REG_FOP> fop;          ///< reg.
        };
    };
    //! @brief Implement Architecture interface for X86.
    UNICORN_HPP_IMPL_ARCH(X86);
#endif
}

#endif  // UNICORN_HPP
