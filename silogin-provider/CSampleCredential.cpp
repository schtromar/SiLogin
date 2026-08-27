//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#include "pch.h"
#include <unknwn.h>
#include "CSampleCredential.h"
#include "guid.h"

#include <memory>
#include <string>

CSampleCredential::CSampleCredential():
    _logger(LogLevel::Debug),
    _authenticationService(_logger),
    _secondFactorVerified(false),
    _useRecoveryAuthentication(false),
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fChecked(false),
    _fShowControls(false),
    _dwComboIndex(0)
{
    DllAddRef();

    _logger.addSink(
        std::make_shared<DebugLogSink>());

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CSampleCredential::~CSampleCredential()
{
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        const size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }

    if (_rgFieldStrings[SFI_SMARTCARD_PIN])
    {
        const size_t pinLength = wcslen(_rgFieldStrings[SFI_SMARTCARD_PIN]);
        SecureZeroMemory(_rgFieldStrings[SFI_SMARTCARD_PIN], pinLength * sizeof(*_rgFieldStrings[SFI_SMARTCARD_PIN]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}


// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT CSampleCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                      _In_ ICredentialProviderUser *pcpUser)
{
    HRESULT hr = S_OK;
    _cpus = cpus;

    GUID guidProvider;
    pcpUser->GetProviderID(&guidProvider);
    _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"SiLogin credential", &_rgFieldStrings[SFI_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"SiLogin smart-card sign-in", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }

    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_EDIT_TEXT]);
    }
    
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_SMARTCARD_PIN]);
    }
    if (SUCCEEDED(hr) && false)
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr) && false)
    {
        hr = SHStrDupW(L"Checkbox", &_rgFieldStrings[SFI_CHECKBOX]);
    }
    if (SUCCEEDED(hr) && false)
    {
        hr = SHStrDupW(L"Combobox", &_rgFieldStrings[SFI_COMBOBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Use recovery key", &_rgFieldStrings[SFI_LAUNCHWINDOW_LINK]);
    }
    if (SUCCEEDED(hr) && false)
    {
        hr = SHStrDupW(L"Hide additional controls", &_rgFieldStrings[SFI_HIDECONTROLS_LINK]);
    }
    if (SUCCEEDED(hr) && true)
    {
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    }
    if (SUCCEEDED(hr) && false)
    {
        PWSTR pszUserName;
        pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);
        if (pszUserName != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"User Name: %s", pszUserName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_FULLNAME_TEXT]);
            CoTaskMemFree(pszUserName);
        }
        else
        {
            hr =  SHStrDupW(L"User Name is NULL", &_rgFieldStrings[SFI_FULLNAME_TEXT]);
        }
    }
    if (SUCCEEDED(hr) && false)
    {
        PWSTR pszDisplayName;
        pcpUser->GetStringValue(PKEY_Identity_DisplayName, &pszDisplayName);
        if (pszDisplayName != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Display Name: %s", pszDisplayName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
            CoTaskMemFree(pszDisplayName);
        }
        else
        {
            hr = SHStrDupW(L"Display Name is NULL", &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(
            L"Insert your enrolled Slovenian eID card and select Sign in.",
            &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
    }

    if (SUCCEEDED(hr) && true)
    {
        hr = pcpUser->GetSid(&_pszUserSid);
    }

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    if (pbAutoLogon == nullptr)
    {
        return E_INVALIDARG;
    }

    // The normal smart-card path has no editable fields. Asking LogonUI to
    // auto-logon is the supported way to invoke GetSerialization when the
    // user selects this local-account tile.
    *pbAutoLogon = _fIsLocalUser ? TRUE : FALSE;

    _secondFactorVerified = false;
    _useRecoveryAuthentication = false;

    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->BeginFieldUpdates();
        _pCredProvCredentialEvents->SetFieldState(
            this, SFI_PASSWORD, CPFS_HIDDEN);
        _pCredProvCredentialEvents->SetFieldState(
            this, SFI_SUBMIT_BUTTON, CPFS_HIDDEN);
        _pCredProvCredentialEvents->SetFieldInteractiveState(
            this, SFI_PASSWORD, CPFIS_NONE);
        _pCredProvCredentialEvents->SetFieldString(
            this, SFI_LAUNCHWINDOW_LINK, L"Use recovery key");
        _pCredProvCredentialEvents->EndFieldUpdates();
    }

    return SetStatusField(
        L"Insert your enrolled Slovenian eID card and select Sign in.");
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
{
    _secondFactorVerified = false;
    _useRecoveryAuthentication = false;

    HRESULT hr = S_OK;

    auto clearSecretField =
        [this, &hr](DWORD fieldId)
    {
        if (_rgFieldStrings[fieldId] == nullptr)
        {
            return;
        }

        const size_t length =
            wcslen(_rgFieldStrings[fieldId]);

        SecureZeroMemory(
            _rgFieldStrings[fieldId],
            length * sizeof(*_rgFieldStrings[fieldId]));

        CoTaskMemFree(_rgFieldStrings[fieldId]);
        _rgFieldStrings[fieldId] = nullptr;

        const HRESULT duplicateResult =
            SHStrDupW(L"", &_rgFieldStrings[fieldId]);

        if (FAILED(duplicateResult))
        {
            hr = duplicateResult;
            return;
        }

        if (_pCredProvCredentialEvents != nullptr)
        {
            _pCredProvCredentialEvents->SetFieldString(
                this,
                fieldId,
                L"");
        }
    };

    clearSecretField(SFI_PASSWORD);
    clearSecretField(SFI_SMARTCARD_PIN);

    SetStatusField(
        L"Insert your enrolled Slovenian eID card and select Sign in.");

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if ((SFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

    if (SFI_SUBMIT_BUTTON == dwFieldID)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to
        // appear next to.
        *pdwAdjacentTo = SFI_PASSWORD;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];

        if (*ppwszStored != nullptr &&
            dwFieldID == SFI_PASSWORD)
        {
            const size_t secretLength = wcslen(*ppwszStored);
            SecureZeroMemory(
                *ppwszStored,
                secretLength * sizeof(**ppwszStored));
        }

        CoTaskMemFree(*ppwszStored);
        *ppwszStored = nullptr;
        hr = SHStrDupW(pwz, ppwszStored);

        if (SUCCEEDED(hr) &&
            dwFieldID == SFI_PASSWORD)
        {
            _secondFactorVerified = false;
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT CSampleCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    HRESULT hr;
    *ppwszLabel = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pbChecked = _fChecked;
        hr = SHStrDupW(_rgFieldStrings[SFI_CHECKBOX], ppwszLabel);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets whether the specified checkbox is checked or not.
HRESULT CSampleCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _fChecked = bChecked;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    HRESULT hr;
    *pcItems = 0;
    *pdwSelectedItem = 0;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    HRESULT hr;
    *ppwszItem = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user changes the selected item in the combobox.
HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user clicks a command link.
HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    HRESULT hr = S_OK;

    CREDENTIAL_PROVIDER_FIELD_STATE cpfsShow = CPFS_HIDDEN;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        switch (dwFieldID)
        {
        case SFI_LAUNCHWINDOW_LINK:
            _useRecoveryAuthentication = !_useRecoveryAuthentication;
            _secondFactorVerified = false;

            if (_pCredProvCredentialEvents != nullptr)
            {
                _pCredProvCredentialEvents->BeginFieldUpdates();
                _pCredProvCredentialEvents->SetFieldState(
                    this,
                    SFI_PASSWORD,
                    _useRecoveryAuthentication
                        ? CPFS_DISPLAY_IN_SELECTED_TILE
                        : CPFS_HIDDEN);
                _pCredProvCredentialEvents->SetFieldState(
                    this,
                    SFI_SUBMIT_BUTTON,
                    _useRecoveryAuthentication
                        ? CPFS_DISPLAY_IN_SELECTED_TILE
                        : CPFS_HIDDEN);
                _pCredProvCredentialEvents->SetFieldInteractiveState(
                    this,
                    SFI_PASSWORD,
                    _useRecoveryAuthentication ? CPFIS_FOCUSED : CPFIS_NONE);
                _pCredProvCredentialEvents->SetFieldString(
                    this,
                    SFI_LAUNCHWINDOW_LINK,
                    _useRecoveryAuthentication
                        ? L"Use smart card"
                        : L"Use recovery key");
                _pCredProvCredentialEvents->EndFieldUpdates();
            }

            SetStatusField(_useRecoveryAuthentication
                ? L"Insert the recovery drive, enter the Windows password, and select Sign in."
                : L"Insert your enrolled Slovenian eID card and select Sign in.");
            break;
        case SFI_HIDECONTROLS_LINK:
            _pCredProvCredentialEvents->BeginFieldUpdates();
            cpfsShow = _fShowControls ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_FULLNAME_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_DISPLAYNAME_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_LOGONSTATUS_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_CHECKBOX, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_EDIT_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_COMBOBOX, cpfsShow);
            _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_HIDECONTROLS_LINK, _fShowControls? L"Hide additional controls" : L"Show additional controls");
            _pCredProvCredentialEvents->EndFieldUpdates();
            _fShowControls = !_fShowControls;
            break;
        default:
            hr = E_INVALIDARG;
        }

    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

std::string CSampleCredential::WideToUtf8(
    PCWSTR value)
{
    if (value == nullptr ||
        *value == L'\0')
    {
        return {};
    }

    const int characterCount =
        static_cast<int>(
            wcslen(value));

    const int requiredBytes =
        WideCharToMultiByte(
            CP_UTF8,
            0,
            value,
            characterCount,
            nullptr,
            0,
            nullptr,
            nullptr);

    if (requiredBytes <= 0)
    {
        return {};
    }

    std::string result(
        static_cast<std::size_t>(
            requiredBytes),
        '\0');

    if (WideCharToMultiByte(
            CP_UTF8,
            0,
            value,
            characterCount,
            result.data(),
            requiredBytes,
            nullptr,
            nullptr) <= 0)
    {
        return {};
    }

    return result;
}

HRESULT CSampleCredential::SetStatusField(
    PCWSTR text)
{
    if (text == nullptr)
    {
        return E_INVALIDARG;
    }

    CoTaskMemFree(
        _rgFieldStrings[SFI_LOGONSTATUS_TEXT]);

    _rgFieldStrings[SFI_LOGONSTATUS_TEXT] =
        nullptr;

    HRESULT hr = SHStrDupW(
        text,
        &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);

    if (SUCCEEDED(hr) &&
        _pCredProvCredentialEvents != nullptr)
    {
        hr = _pCredProvCredentialEvents
            ->SetFieldString(
                this,
                SFI_LOGONSTATUS_TEXT,
                _rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
    }

    return hr;
}

HRESULT CSampleCredential::VerifySecondFactor(
    _Outptr_result_maybenull_ PWSTR* optionalStatusText,
    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON* optionalStatusIcon)
{
    if (optionalStatusText == nullptr ||
        optionalStatusIcon == nullptr)
    {
        return E_INVALIDARG;
    }

    *optionalStatusText = nullptr;
    *optionalStatusIcon = CPSI_NONE;

    if (_pszUserSid == nullptr)
    {
        SHStrDupW(
            L"Windows did not provide a user SID.",
            optionalStatusText);

        *optionalStatusIcon = CPSI_ERROR;
        return S_FALSE;
    }

    const std::string selectedSid =
        WideToUtf8(_pszUserSid);

    if (selectedSid.empty())
    {
        SHStrDupW(
            L"Could not read the selected Windows account SID.",
            optionalStatusText);

        *optionalStatusIcon = CPSI_ERROR;
        return S_FALSE;
    }

    SetStatusField(
        _useRecoveryAuthentication
            ? L"Checking recovery drive..."
            : L"Checking smart card...");

    AuthenticationResult result;

    if (_useRecoveryAuthentication)
    {
        result = _authenticationService
            .authenticateWithRecoveryForAccount(
                selectedSid);
    }
    else
    {
        result = _authenticationService
            .authenticateWithCardForAccount(
                selectedSid);
    }

    if (!result.succeeded())
    {
        _secondFactorVerified = false;

        SHStrDupW(
            _useRecoveryAuthentication
                ? L"Recovery authentication failed."
                : L"Smart-card authentication failed. Check the card.",
            optionalStatusText);

        *optionalStatusIcon = CPSI_ERROR;

        SetStatusField(
            _useRecoveryAuthentication
                ? L"Recovery authentication failed."
                : L"Smart-card authentication failed. Check the card and try again.");

        return S_FALSE;
    }

    if (!result.identity ||
        result.identity->accountSid != selectedSid)
    {
        _secondFactorVerified = false;

        SHStrDupW(
            L"The smart card or recovery key belongs to another Windows account.",
            optionalStatusText);

        *optionalStatusIcon = CPSI_ERROR;

        SetStatusField(
            L"Second factor belongs to another user.");

        return S_FALSE;
    }

    _secondFactorVerified = true;

    SetStatusField(
        _useRecoveryAuthentication
            ? L"Recovery key verified. Submitting Windows password..."
            : L"Smart card verified.");

    return S_OK;
}

// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
HRESULT CSampleCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                            _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                            _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                            _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    // Passwordless local-account path: obtain a one-time AP challenge, sign it
    // with the enrolled card, and submit the proof directly to SiLogin.
    if (_fIsLocalUser && !_useRecoveryAuthentication && _pszUserSid != nullptr)
    {
        const std::string selectedSid = WideToUtf8(_pszUserSid);
        LsaLogonChallenge challenge;
        ULONG packageId = 0;
        hr = RequestSiLoginChallenge(selectedSid, challenge, &packageId);
        if (FAILED(hr))
        {
            SHStrDupW(L"Could not obtain a SiLogin challenge.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return S_OK;
        }

        const std::optional<LsaLogonProof> proof =
            _authenticationService.createLogonProof(challenge);
        if (!proof)
        {
            SHStrDupW(L"The smart card proof could not be created.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return S_OK;
        }

        try
        {
            const auto serialized = LsaAuthenticationProtocol::serializeProof(*proof);
            pcpcs->rgbSerialization = static_cast<byte*>(
                CoTaskMemAlloc(serialized.size()));
            if (!pcpcs->rgbSerialization) return E_OUTOFMEMORY;
            memcpy(pcpcs->rgbSerialization, serialized.data(), serialized.size());
            pcpcs->cbSerialization = static_cast<ULONG>(serialized.size());
            pcpcs->ulAuthenticationPackage = packageId;
            pcpcs->clsidCredentialProvider = CLSID_CSample;
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
            SetStatusField(L"Smart-card proof created. Signing in...");
            return S_OK;
        }
        catch (...)
        {
            SHStrDupW(L"The SiLogin proof could not be serialized.", ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return E_FAIL;
        }
    }

    if (_rgFieldStrings[SFI_PASSWORD] == nullptr ||
        _rgFieldStrings[SFI_PASSWORD][0] == L'\0')
    {
        SHStrDupW(
            L"Enter your Windows password.",
            ppwszOptionalStatusText);

        *pcpsiOptionalStatusIcon =
            CPSI_WARNING;

        SetStatusField(
            L"Enter your Windows password.");

        return S_OK;
    }

    if (!_secondFactorVerified)
    {
        const HRESULT verificationResult =
            VerifySecondFactor(
                ppwszOptionalStatusText,
                pcpsiOptionalStatusIcon);

        if (verificationResult != S_OK)
        {
            *pcpgsr =
                CPGSR_NO_CREDENTIAL_NOT_FINISHED;

            ZeroMemory(
                pcpcs,
                sizeof(*pcpcs));

            return S_OK;
        }
    }

    // For local user, the domain and user name can be split from _pszQualifiedUserName (domain\username).
    // CredPackAuthenticationBuffer() cannot be used because it won't work with unlock scenario.
    if (_fIsLocalUser)
    {
        PWSTR pwzProtectedPassword;
        hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);
        if (SUCCEEDED(hr))
        {
            PWSTR pszDomain;
            PWSTR pszUsername;
            hr = SplitDomainAndUsername(_pszQualifiedUserName, &pszDomain, &pszUsername);
            if (SUCCEEDED(hr))
            {
                KERB_INTERACTIVE_UNLOCK_LOGON kiul;
                hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
                if (SUCCEEDED(hr))
                {
                    // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
                    // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                    // as necessary.
                    hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                    if (SUCCEEDED(hr))
                    {
                        ULONG ulAuthPackage;
                        hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                        if (SUCCEEDED(hr))
                        {
                            pcpcs->ulAuthenticationPackage = ulAuthPackage;
                            pcpcs->clsidCredentialProvider = CLSID_CSample;
                            // At this point the credential has created the serialized credential used for logon
                            // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                            // that we have all the information we need and it should attempt to submit the
                            // serialized credential.
                            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        }
                    }
                }
                CoTaskMemFree(pszDomain);
                CoTaskMemFree(pszUsername);
            }
            CoTaskMemFree(pwzProtectedPassword);
        }
    }
    else
    {
        DWORD dwAuthFlags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;

        // First get the size of the authentication buffer to allocate
        if (!CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(_rgFieldStrings[SFI_PASSWORD]), nullptr, &pcpcs->cbSerialization) &&
            (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
        {
            pcpcs->rgbSerialization = static_cast<byte *>(CoTaskMemAlloc(pcpcs->cbSerialization));
            if (pcpcs->rgbSerialization != nullptr)
            {
                hr = S_OK;

                // Retrieve the authentication buffer
                if (CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(_rgFieldStrings[SFI_PASSWORD]), pcpcs->rgbSerialization, &pcpcs->cbSerialization))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_CSample;

                        // At this point the credential has created the serialized credential used for logon
                        // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                        // that we have all the information we need and it should attempt to submit the
                        // serialized credential.
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    }
                }
                else
                {
                    hr = HRESULT_FROM_WIN32(GetLastError());
                    if (SUCCEEDED(hr))
                    {
                        hr = E_FAIL;
                    }
                }

                if (FAILED(hr))
                {
                    CoTaskMemFree(pcpcs->rgbSerialization);
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
    }
    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PCWSTR    pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, 0, L"The smart-card proof was rejected.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }
    else if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        // Keep the raw codes visible while the custom authentication package is
        // being validated.  LogonUI's stock messages collapse several very
        // different failures into "The user account does not exist".
        wchar_t diagnostic[160]{};
        swprintf_s(diagnostic, ARRAYSIZE(diagnostic),
            L"SiLogin failed (status 0x%08X, substatus 0x%08X).",
            static_cast<unsigned long>(ntsStatus),
            static_cast<unsigned long>(ntsSubstatus));
        if (SUCCEEDED(SHStrDupW(diagnostic, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        }
    }

    // If we failed the logon, try to erase the password field.
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        _secondFactorVerified = false;

        wchar_t statusText[192]{};
        swprintf_s(statusText, ARRAYSIZE(statusText),
            _useRecoveryAuthentication
                ? L"Recovery sign-in failed (0x%08X / 0x%08X)."
                : L"Smart-card sign-in failed (0x%08X / 0x%08X).",
            static_cast<unsigned long>(ntsStatus),
            static_cast<unsigned long>(ntsSubstatus));
        SetStatusField(statusText);

        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
        }

        if (_rgFieldStrings[SFI_SMARTCARD_PIN] != nullptr)
        {
            const size_t pinLength = wcslen(_rgFieldStrings[SFI_SMARTCARD_PIN]);
            SecureZeroMemory(
                _rgFieldStrings[SFI_SMARTCARD_PIN],
                pinLength * sizeof(*_rgFieldStrings[SFI_SMARTCARD_PIN]));

            CoTaskMemFree(_rgFieldStrings[SFI_SMARTCARD_PIN]);
            _rgFieldStrings[SFI_SMARTCARD_PIN] = nullptr;
            SHStrDupW(L"", &_rgFieldStrings[SFI_SMARTCARD_PIN]);
        }
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT CSampleCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    else if (dwFieldID == SFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}
