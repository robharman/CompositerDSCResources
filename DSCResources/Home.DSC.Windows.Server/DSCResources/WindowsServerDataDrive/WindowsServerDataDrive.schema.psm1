Configuration WindowsServerDataDrive {
    param (
        [Parameter(Mandatory = $False)]
        [string]
        $DriveLetter        =   'B',

        [Parameter(Mandatory = $False)]
        [int32]
        $DiskID             =   1,

        [Parameter(Mandatory = $False)]
        [string]
        $FSLabel            =   'Data',

        [Parameter(Mandatory = $False)]
        [switch]
        $EnableDedup,

        [Parameter(Mandatory = $False)]
        [switch]
        $OptimizeInUseFiles,

        [Parameter(Mandatory = $False)]
        [switch]
        $OptimizePartialFiles,

        [Parameter(Mandatory = $False)]
        [int32]
        $MinimumFileAgeDays =   3
    )

    Import-DSCResource -ModuleName 'PSDscResources'
    Import-DscResource -ModuleName 'StorageDSC'

    $Volume                 =   "$($DriveLetter):"

    Disk "Mount_DataDrive_$DriveLetter" {
        DriveLetter         =   $DriveLetter
        DiskId              =   $DiskID
        PartitionStyle      =   'GPT'
        FSLabel             =   $FSLabel
        FSFormat            =   'NTFS'
    }

    if ($EnableDedup){

        WindowsFeature EnableDedupForDataVolume {
            Ensure          =   'Present'
            Name            =   'FS-Data-Deduplication'
        }

        Script EnableDedup {
            GetScript = {
                try {
                    @{Result = (Get-DedupStatus -Volume $Using:Volume)}
                }catch {
                    @{Result = 'Not configured'}
                }
            }

            TestScript = {

                try {
                    return (Get-DedupVolume -Volume $Using:Volume -ErrorAction 'Stop').Enabled

                }catch {
                    return $False
                }
            }

            SetScript   =   {
                Enable-DedupVolume $Volume
                $DedupParams    =   @{
                    OptimizeInUseFiles      =   $Using:OptimizeInUseFiles
                    OptimizePartialFiles    =   $Using:OptimizePartialFiles
                    MinimumFileAgeDays      =   $Using:MinimumFileAgeDays
                    Volume                  =   $Using:Volume
                }

                Set-DedupVolume @DedupParams
            }
        }
    }
}