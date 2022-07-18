Light wrapper around [unicorn engine](https://github.com/unicorn-engine/unicorn) for C++20.  

# Advantages over using raw C API

API names are kept as close as possible to original C names.  

Enums are wrapped in type safe C++ enum class variants.  

Keeps global namespace clean by including unicorn.h inside a namespace.  

Provides RAII wrapper for owning types like: 
  - engine handle
  - engine state
  - hook

Convienient and autocomplete friendly access to registers for each platform.  

# Example 

More examples [here](tests/test_example.cpp) and [here](tests/test_x86.cpp)

```cpp
// creating engine
auto uc = uc::EngineOwner(uc::X86::MODE_32, "Creating example uc engine!");

// setting registers using * operator
*uc->reg.eax = 10;

// setting registers with bitcasting
uc->reg.eax.write_bitcast<float>(10.5);


constexpr auto callback = [](uc::EngineHandle<uc::X86> uc) {
    // Store port in userdata
    *user_data = port;
};

// RAII managed hooks
if (auto result = uc->hook.add_insn_sysenter<+callback>(uc::mem::Range())) {
    // hook is automatically released at the end of scope
}
```
