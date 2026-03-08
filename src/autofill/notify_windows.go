//go:build windows

package autofill

import (
	"encoding/base64"
	"io"
	"os/exec"
	"strings"
	"unicode/utf16"
)

type PopupNotifier interface {
	Show(message string)
}

type windowsPopupNotifier struct{}

func newPopupNotifier() PopupNotifier {
	return windowsPopupNotifier{}
}

func (windowsPopupNotifier) Show(message string) {
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	go spawnWindowsPopup(message)
}

func spawnWindowsPopup(message string) {
	escapedMessage := strings.ReplaceAll(message, "'", "''")
	script := strings.ReplaceAll(windowsPopupScriptTemplate, "__APM_MESSAGE__", escapedMessage)
	encoded := encodePowerShellScript(script)

	cmd := exec.Command(
		"powershell",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-STA",
		"-WindowStyle", "Hidden",
		"-EncodedCommand", encoded,
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return
	}
	if cmd.Process != nil {
		_ = cmd.Process.Release()
	}
}

func encodePowerShellScript(script string) string {
	u16 := utf16.Encode([]rune(script))
	buf := make([]byte, len(u16)*2)
	for i, v := range u16 {
		buf[i*2] = byte(v)
		buf[i*2+1] = byte(v >> 8)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

const windowsPopupScriptTemplate = `
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Width="430" Height="96"
        WindowStyle="None"
        AllowsTransparency="True"
        Background="Transparent"
        Topmost="True"
        ShowInTaskbar="False"
        ResizeMode="NoResize"
        Opacity="0">
  <Border CornerRadius="14" Background="#E6000000" BorderBrush="#404040" BorderThickness="1" Padding="14">
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*" />
        <ColumnDefinition Width="22" />
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0">
        <TextBlock Text="APM Autofill" Foreground="#E8E8E8" FontSize="12" FontWeight="Bold" />
        <TextBlock x:Name="MessageText" Margin="0,6,0,0" Foreground="#FFFFFF" FontSize="12" TextWrapping="Wrap" />
      </StackPanel>
      <Button x:Name="CloseButton" Grid.Column="1" Content="×" FontSize="14" FontWeight="Bold"
              Foreground="#E8E8E8" Background="Transparent" BorderBrush="Transparent"
              Padding="0" Width="20" Height="20" HorizontalAlignment="Right" VerticalAlignment="Top" Cursor="Hand" />
    </Grid>
  </Border>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)
$messageText = $window.FindName("MessageText")
$closeButton = $window.FindName("CloseButton")
$messageText.Text = '__APM_MESSAGE__'

$workArea = [System.Windows.SystemParameters]::WorkArea
$window.Left = $workArea.Right - $window.Width - 22
$window.Top = $workArea.Bottom - $window.Height - 22

$fadeOutAction = {
    $fadeOut = New-Object System.Windows.Media.Animation.DoubleAnimation
    $fadeOut.From = $window.Opacity
    $fadeOut.To = 0
    $fadeOut.Duration = [TimeSpan]::FromMilliseconds(180)
    $fadeOut.Add_Completed({ $window.Close() })
    $window.BeginAnimation([System.Windows.Window]::OpacityProperty, $fadeOut)
}

$closeButton.Add_Click({
    & $fadeOutAction
})

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(5)
$timer.Add_Tick({
    $timer.Stop()
    & $fadeOutAction
})

$window.Add_ContentRendered({
    $fadeIn = New-Object System.Windows.Media.Animation.DoubleAnimation
    $fadeIn.From = 0
    $fadeIn.To = 1
    $fadeIn.Duration = [TimeSpan]::FromMilliseconds(180)
    $window.BeginAnimation([System.Windows.Window]::OpacityProperty, $fadeIn)
    $timer.Start()
})

$window.ShowDialog() | Out-Null
`
