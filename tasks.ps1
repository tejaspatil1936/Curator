# Curator development tasks for Windows PowerShell (tasks.ps1)
param (
    [Parameter(Position = 0)]
    [string]$Task = "help"
)

switch ($Task.ToLower()) {
    "eval" {
        Write-Host "Running Curator Accuracy Harness..." -ForegroundColor Cyan
        docker exec curator-curator-api-1 python -m curator.eval.harness
    }
    "up" {
        docker compose up --build -d
    }
    "down" {
        docker compose down
    }
    "logs" {
        docker compose logs -f --tail=100
    }
    "psql" {
        docker exec -it curator-curator-db-1 psql -U curator -d curator
    }
    default {
        Write-Host "Curator PowerShell Tasks:" -ForegroundColor Yellow
        Write-Host "  .\tasks.ps1 eval   - Run accuracy harness against ground truth"
        Write-Host "  .\tasks.ps1 up     - Start docker compose"
        Write-Host "  .\tasks.ps1 down   - Stop docker compose"
        Write-Host "  .\tasks.ps1 logs   - Tail logs"
        Write-Host "  .\tasks.ps1 psql   - Open database shell"
    }
}
