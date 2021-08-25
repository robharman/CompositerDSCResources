Configuration WindowsServerPowerPlan {
    Import-DscResource -ModuleName "ComputerManagementDSC"
    
    PowerPlan SetPlanHighPerformance {
        IsSingleInstance    =   'Yes'
        Name                =   'High performance'
    }
}