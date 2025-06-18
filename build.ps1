# 设置变量
$srcDir = "src"
$outDir = "out"
$mainClass = "MailClient.MainFrame"
$libDir = "lib"
$jarName = "MailClientApp.jar"

# 创建输出目录
if (!(Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

# 收集依赖 jar
$libs = Get-ChildItem -Path $libDir -Filter *.jar | ForEach-Object { $_.FullName }
$cp = $libs -join ";"

# 编译 Java 文件
Write-Host "Compiling..."
javac -cp $cp -d $outDir (Get-ChildItem -Recurse -Filter *.java -Path $srcDir | ForEach-Object { $_.FullName })

# 创建可运行 jar
Write-Host "Packaging..."
Set-Content -Path "$outDir\manifest.txt" -Value "Main-Class: $mainClass`nClass-Path: $cp`n"

jar cfm $jarName "$outDir\manifest.txt" -C $outDir .

Write-Host "Build complete: $jarName"
