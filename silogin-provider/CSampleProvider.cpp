//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// CSampleProvider implements ICredentialProvider, which is the main
// interface that logonUI uses to decide which tiles to display.
// In this sample, we will display one tile that uses each of the nine
// available UI controls.

#include "pch.h"
#include <initguid.h>
#include "CSampleProvider.h"
#include "CSampleCredential.h"
#include "guid.h"
#include "../libsilogin/IdentityStore.h"

#include <algorithm>

namespace
{
    std::string SidToUtf8(PCWSTR sid)
    {
        if (sid == nullptr) return {};
        const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
            sid, -1, nullptr, 0, nullptr, nullptr);
        if (size <= 1) return {};
        std::string value(static_cast<size_t>(size), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, sid, -1,
            value.data(), size, nullptr, nullptr) == 0)
            return {};
        value.pop_back();
        return value;
    }
}

CSampleProvider::CSampleProvider():
    _cRef(1),
    _fRecreateEnumeratedCredentials(true),
    _cpus(CPUS_INVALID),
    _pCredProviderUserArray(nullptr),
    _pCredProviderEvents(nullptr),
    _upAdviseContext(0),
    _pendingSubmitCredential(nullptr)
{
    DllAddRef();
}

CSampleProvider::~CSampleProvider()
{
    _ReleaseEnumeratedCredentials();
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }
    if (_pCredProviderEvents != nullptr)
    {
        _pCredProviderEvents->Release();
        _pCredProviderEvents = nullptr;
    }

    DllRelease();
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT CSampleProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD /*dwFlags*/)
{
    HRESULT hr;

    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // The reason why we need _fRecreateEnumeratedCredentials is because ICredentialProviderSetUserArray::SetUserArray() is called after ICredentialProvider::SetUsageScenario(),
        // while we need the ICredentialProviderUserArray during enumeration in ICredentialProvider::GetCredentialCount()
        _cpus = cpus;
        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }

    return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt.  It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a tile.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// If you wish to see an example of SetSerialization, please see either the SampleCredentialProvider
// sample or the SampleCredUICredentialProvider sample.  [The logonUI team says, "The original sample that
// this was built on top of didn't have SetSerialization.  And when we decided SetSerialization was
// important enough to have in the sample, it ended up being a non-trivial amount of work to integrate
// it into the main sample.  We felt it was more important to get these samples out to you quickly than to
// hold them in order to do the work to integrate the SetSerialization changes from SampleCredentialProvider
// into this sample.]
HRESULT CSampleProvider::SetSerialization(
    _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const * /*pcpcs*/)
{
    return E_NOTIMPL;
}

// Called by LogonUI to give you a callback.  Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated.
HRESULT CSampleProvider::Advise(
    _In_ ICredentialProviderEvents *pcpe,
    _In_ UINT_PTR upAdviseContext)
{
    if (pcpe == nullptr)
    {
        return E_INVALIDARG;
    }

    if (_pCredProviderEvents != nullptr)
    {
        _pCredProviderEvents->Release();
    }

    _pCredProviderEvents = pcpe;
    _pCredProviderEvents->AddRef();
    _upAdviseContext = upAdviseContext;
    return S_OK;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT CSampleProvider::UnAdvise()
{
    _pendingSubmitCredential = nullptr;
    _upAdviseContext = 0;

    if (_pCredProviderEvents != nullptr)
    {
        _pCredProviderEvents->Release();
        _pCredProviderEvents = nullptr;
    }

    return S_OK;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired
// using the field descriptors.
HRESULT CSampleProvider::GetFieldDescriptorCount(
    _Out_ DWORD *pdwCount)
{
    *pdwCount = SFI_NUM_FIELDS;
    return S_OK;
}

// Gets the field descriptor for a particular field.
HRESULT CSampleProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    HRESULT hr;
    *ppcpfd = nullptr;

    // Verify dwIndex is a valid field.
    if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
// The default tile is the tile which will be shown in the zoomed view by default. If
// more than one provider specifies a default the last used cred prov gets to pick
// the default. If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call
// GetSerialization on the credential you've specified as the default and will submit
// that credential for authentication without showing any further UI.
HRESULT CSampleProvider::GetCredentialCount(
    _Out_ DWORD *pdwCount,
    _Out_ DWORD *pdwDefault,
    _Out_ BOOL *pbAutoLogonWithDefault)
{
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

    if (_fRecreateEnumeratedCredentials)
    {
        _fRecreateEnumeratedCredentials = false;
        _ReleaseEnumeratedCredentials();
        _CreateEnumeratedCredentials();
    }

    *pdwCount = static_cast<DWORD>(_credentials.size());

    if (_pendingSubmitCredential != nullptr)
    {
        const auto requested = std::find(
            _credentials.begin(),
            _credentials.end(),
            _pendingSubmitCredential);

        if (requested != _credentials.end())
        {
            *pdwDefault = static_cast<DWORD>(
                std::distance(_credentials.begin(), requested));
            *pbAutoLogonWithDefault = TRUE;
        }

        // A command-link click authorizes exactly one submission attempt.
        _pendingSubmitCredential = nullptr;
    }

    return S_OK;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT CSampleProvider::GetCredentialAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc)
{
    HRESULT hr = E_INVALIDARG;
    *ppcpc = nullptr;

    if (ppcpc != nullptr && dwIndex < _credentials.size())
    {
        hr = _credentials[dwIndex]->QueryInterface(IID_PPV_ARGS(ppcpc));
    }
    return hr;
}

// This function will be called by LogonUI after SetUsageScenario succeeds.
// Sets the User Array with the list of users to be enumerated on the logon screen.
HRESULT CSampleProvider::SetUserArray(_In_ ICredentialProviderUserArray *users)
{
    if (_pCredProviderUserArray)
    {
        _pCredProviderUserArray->Release();
    }
    _pCredProviderUserArray = users;
    _pCredProviderUserArray->AddRef();
    _fRecreateEnumeratedCredentials = true;
    return S_OK;
}

HRESULT CSampleProvider::RequestSubmit(
    _In_ CSampleCredential *credential)
{
    if (credential == nullptr || _pCredProviderEvents == nullptr)
    {
        return E_UNEXPECTED;
    }

    if (std::find(_credentials.begin(), _credentials.end(), credential) ==
        _credentials.end())
    {
        return E_INVALIDARG;
    }

    _pendingSubmitCredential = credential;
    const HRESULT hr = _pCredProviderEvents->CredentialsChanged(
        _upAdviseContext);
    if (FAILED(hr))
    {
        _pendingSubmitCredential = nullptr;
    }

    return hr;
}

void CSampleProvider::_CreateEnumeratedCredentials()
{
    switch (_cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        {
            _EnumerateCredentials();
            break;
        }
    default:
        break;
    }
}

void CSampleProvider::_ReleaseEnumeratedCredentials()
{
    _pendingSubmitCredential = nullptr;
    for (CSampleCredential* credential : _credentials)
    {
        credential->DetachProvider();
        credential->Release();
    }
    _credentials.clear();
}

HRESULT CSampleProvider::_EnumerateCredentials()
{
    if (_pCredProviderUserArray == nullptr) return S_OK;

    DWORD userCount = 0;
    HRESULT hr = _pCredProviderUserArray->GetCount(&userCount);
    if (FAILED(hr)) return hr;

    for (DWORD index = 0; index < userCount; ++index)
    {
        ICredentialProviderUser* user = nullptr;
        hr = _pCredProviderUserArray->GetAt(index, &user);
        if (FAILED(hr)) return hr;

        GUID providerId{};
        PWSTR sid = nullptr;
        const HRESULT providerResult = user->GetProviderID(&providerId);
        const HRESULT sidResult = user->GetSid(&sid);
        bool enrolledLocalUser = false;
        if (SUCCEEDED(providerResult) && SUCCEEDED(sidResult) &&
            providerId == Identity_LocalUserProvider)
        {
            try
            {
                const std::string sidUtf8 = SidToUtf8(sid);
                enrolledLocalUser = !sidUtf8.empty() &&
                    IdentityStore(sidUtf8).load().has_value();
            }
            catch (...) { enrolledLocalUser = false; }
        }

        CoTaskMemFree(sid);
        if (!enrolledLocalUser) { user->Release(); continue; }

        CSampleCredential* credential = new(std::nothrow) CSampleCredential();
        if (credential == nullptr) { user->Release(); return E_OUTOFMEMORY; }
        hr = credential->Initialize(_cpus, s_rgCredProvFieldDescriptors,
            s_rgFieldStatePairs, user, this);
        user->Release();
        if (FAILED(hr)) { credential->Release(); return hr; }
        try { _credentials.push_back(credential); }
        catch (...) { credential->Release(); return E_OUTOFMEMORY; }
    }
    return S_OK;
}

// Boilerplate code to create our provider.
HRESULT CSample_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
    HRESULT hr;
    CSampleProvider *pProvider = new(std::nothrow) CSampleProvider();
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}
