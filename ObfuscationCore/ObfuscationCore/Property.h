#pragma once
#include <boost/bind.hpp>
#include <boost/function.hpp>

namespace Utils
{
    template <typename T, 
        const Property::AccessorFlags Flags = Property<T>::GetAndSet>
    class Property
    {
        T member;
        
    public:
        typedef Property<T>     self_t;

        typedef T (*geter_fn_t)();
        typedef void (*seter_fn_t)(const T&);

        enum AccessorFlags{None, Get, Set, GetAndSet}; // 1, 10, 11 (just like flags, GetAndSet = Get|Set ) 

        T DefaultGet()
        {
            return member;
        }

        void DefaultSet(const T& val)
        {
            member = val;
        }

        Property(void)
        {
            if (Flags & Get)
            {

            }
        }

        ~Property(void)
        {
        }

    protected:
        
    };

}
