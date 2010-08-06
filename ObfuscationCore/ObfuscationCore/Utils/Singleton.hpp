#ifndef SINGLETON_H
#define SINGLETON_H

template <class T>
class StaticAllocRecreatable
{
    static char _instance[sizeof(T)];

public:
    static void create(T*& ptr)
    {
        ptr = new(_instance) T(); 
    }

    static void destroy(T*& ptr)
    {
        assert(static_cast<void*>(ptr) == static_cast<void*>(_instance));
        static_cast<T*>(static_cast<void*>(_instance))->~T();
        ptr = 0;
    }

};


template <class T>
class CriticalSectionSync
{
protected:
    WPS::SPI::Mutex * _mutex;

public:
    CriticalSectionSync()
        : _mutex(const_cast<WPS::SPI::Mutex *>(WPS::SPI::Mutex::newInstance()))
    {}

    class Lock
    {
        CriticalSectionSync* _this;
    public:
        Lock(CriticalSectionSync* thisPointer)
            : _this(thisPointer)
        {
            _this->_mutex->acquire();
        }

        ~Lock()
        {
            _this->_mutex->release();
        }
    };
    friend class Lock;

    typedef Lock WriterLock;
    typedef Lock ReaderLock;
};

template <class T>
struct DefaultSingletonTraits
{
    typedef StaticAllocRecreatable<T>   alloc_policy_t;
    typedef CriticalSectionSync<T>      sync_policy_t;  // create/destroy synchronization

    static sync_policy_t _sync;
    friend class alloc_policy_t;
};

/************************************************************************/
/* you can inherit Singleton<T> to make T sequrely singleton  or use it 
as wrapper */
/************************************************************************/
template <
    class T, 
    class TraitsT = DefaultSingletonTraits<T>
>
class Singleton
    : public TraitsT
{
    typedef Singleton<T,TraitsT>    self_t;
    friend class alloc_policy_t;

    static T* _instance;

protected:
    Singleton(){}
    virtual ~Singleton(){}

public:
    static T& instance() 
    {
        TraitsT::sync_policy_t::ReaderLock lock(&_sync);
        if (! _instance)
        {
            TraitsT::sync_policy_t::WriterLock lock(&_sync);
            alloc_policy_t::create(_instance);
            atexit(&self_t::destruct);
        }
        return *static_cast<T*>(_instance);
    }

    static void destruct()
    {
        TraitsT::sync_policy_t::WriterLock lock(&_sync);
        alloc_policy_t::destroy(_instance);
    }
};

template <class T, class TraitsT>
T* Singleton<T, TraitsT>::_instance = 0;

template <class T>
CriticalSectionSync<T> DefaultSingletonTraits<T>::_sync;

template <class T>
char StaticAllocRecreatable<T>::_instance[sizeof(T)];

#endif
