Configuration WindowsServerActivation {

    Import-DSCResource -ModuleName 'PSDSCResources'

    Script WindowsServerActivation {
        GetScript = {
            if (((cscript /Nologo 'C:\Windows\System32\slmgr.vbs' /xpr)[1]) -like '*Automatic VM*') {
                @{ Result               =   'Windows is AVMA activated.' }

            }elseif  (((cscript /Nologo 'C:\Windows\System32\slmgr.vbs' /xpr)[1]) -like '*permanently activated*') {
                @{ Result               =   'Windows is activated.' }

            }elseif (((cscript /Nologo 'C:\Windows\System32\slmgr.vbs' /xpr)[1]) -like '*Notification mode*') {
                @{ Result               =   'Windows is not activated.' }

            }else {
                @{ Result               =   'Cannot determine activation status.' }
            }
        }

        TestScript = {
            if (((cscript /Nologo 'C:\Windows\System32\slmgr.vbs' /xpr)[1]) -like '*Notification mode*') {
                return $False

            }elseif  (((cscript /Nologo 'C:\Windows\System32\slmgr.vbs' /xpr)[1]) -like '*permanently activated*') {
                return $True

            }elseif  (((cscript /Nologo 'C:\Windows\System32\slmgr.vbs' /xpr)[1]) -like '*Automatic VM*') {
                return $True

            }else {
                throw 'Could not determine Windows activation status.'
            }
        }

        SetScript = {
            switch ((Get-ComputerInfo).WindowsProductName) {
                'Windows Server 2019 Datacenter' {
                    $WindowsAVMAKey = 'H3RNG-8C32Q-Q8FRX-6TDXV-WMBMW'
                }

                'Windows Server 2019 Standard' {
                    $WindowsAVMAKey = 'TNK62-RXVTB-4P47B-2D623-4GF74'
                }

                'Windows Server 2016 Datacenter' {
                    $WindowsAVMAKey = 'TMJ3Y-NTRTM-FJYXT-T22BY-CWG3J'
                }

                'Windows Server 2016 Standard' {
                    $WindowsAVMAKey = 'C3RCX-M6NRP-6CXC9-TW2F2-4RHYD'
                }

                'Windows Server 2012 R2 Datacenter' {
                    $WindowsAVMAKey = 'Y4TGP-NPTV9-HTC2H-7MGQ3-DV4TW'
                }

                'Windows Server 2012 R2 Standard' {
                    $WindowsAVMAKey = 'DBGBW-NPF86-BJVTX-K3WKJ-MTB6V'
                }

                # Windows Server SAC releases, this may need to be updated to deal with newer builds in the future.
                'Windows Server Datacenter' {
                    $WindowsAVMAKey = 'H3RNG-8C32Q-Q8FRX-6TDXV-WMBMW'
                }

                Default {
                    throw "Can't determine Windows Server version"
                }
            }

            (cscript /Nologo 'C:\Windows\System32\slmgr.vbs' /ipk $WindowsAVMAKey)
            # Pause to let this happen since _sometimes_ this errors out when it happens too fast
            Start-Sleep 2
            (cscript /Nologo 'C:\Windows\System32\slmgr.vbs' /ato)
        }
    }
}