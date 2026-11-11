using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Suro.Setup
{
    static class Program
    {
        /// <summary>
        /// Double-click: a small window installs or updates the client (one UAC prompt, no questions).
        /// /quiet: no window; exit code 0 on success. Used by approved agent updates.
        /// </summary>
        [STAThread]
        static int Main(string[] args)
        {
            bool quiet = args.Any(a => new[] { "/quiet", "/q", "-quiet", "--quiet" }.Contains(a, StringComparer.OrdinalIgnoreCase));
            var installer = new Installer();
            try { installer.Prepare(); }
            catch (SetupException exception) { return Fail(quiet, installer.Language, exception.Code, exception.Message); }
            if (quiet)
            {
                try { installer.Run(_ => { }); return 0; }
                catch (SetupException exception) { Installer.Log("Failed: " + exception.Message); return exception.Code; }
                catch (Exception exception) { Installer.Log("Failed: " + exception); return 99; }
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            using (var form = new SetupForm(installer)) { Application.Run(form); return form.ExitCode; }
        }

        static int Fail(bool quiet, string language, int code, string message)
        {
            Installer.Log("Failed: " + message);
            if (!quiet)
                MessageBox.Show(Texts.Get(language, "failed") + "\n\nSURO-" + code.ToString("00") + ": " + message,
                    Texts.Get(language, "title"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            return code;
        }
    }

    sealed class SetupForm : Form
    {
        readonly Installer installer;
        readonly Label message = new Label { AutoSize = false, Dock = DockStyle.Top, Height = 120, Padding = new Padding(4) };
        readonly ProgressBar progress = new ProgressBar { Style = ProgressBarStyle.Marquee, Dock = DockStyle.Top, Height = 18, MarqueeAnimationSpeed = 30 };
        readonly Button close = new Button { Dock = DockStyle.Bottom, Height = 44, Visible = false };
        public int ExitCode { get; private set; } = 99;

        public SetupForm(Installer installer)
        {
            this.installer = installer;
            string language = installer.Language;
            Text = Texts.Get(language, "title");
            Font = new Font("Segoe UI", 12f);
            ClientSize = new Size(560, 230);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            Padding = new Padding(20);
            message.Text = Texts.Get(language, "working");
            close.Text = Texts.Get(language, "close");
            close.Click += (_, __) => Close();
            Controls.Add(close);
            Controls.Add(progress);
            Controls.Add(message);
            FormClosing += (_, e) => { if (!close.Visible) e.Cancel = true; };  // never interrupt a half-finished copy
            Shown += async (_, __) => await Install();
        }

        async Task Install()
        {
            string language = installer.Language;
            try
            {
                Outcome outcome = await Task.Run(() => installer.Run(step => BeginInvoke(new Action(() =>
                    message.Text = Texts.Get(language, "working") + "\n\n" + Texts.Get(language, "step." + step)))));
                message.Text = Texts.Get(language, outcome == Outcome.Installed ? "installed" : "updated");
                ExitCode = 0;
            }
            catch (Exception exception)
            {
                int code = exception is SetupException setup ? setup.Code : 99;
                Installer.Log("Failed: " + exception);
                message.Text = Texts.Get(language, "failed") + "\n\nSURO-" + code.ToString("00") + ": " + exception.Message;
                message.ForeColor = Color.Firebrick;
                ExitCode = code;
            }
            progress.Visible = false;
            close.Visible = true;
            close.Focus();
        }
    }

    static class Texts
    {
        static readonly Dictionary<string, Dictionary<string, string>> All = new Dictionary<string, Dictionary<string, string>>
        {
            ["hy"] = new Dictionary<string, string>
            {
                ["title"] = "Suro ծրագրի տեղադրում",
                ["working"] = "Suro ծրագիրը տեղադրվում է։ Խնդրում ենք սպասել և չանջատել համակարգիչը։",
                ["step.stop"] = "Նախապատրաստում…",
                ["step.copy"] = "Ֆայլերի պատճենում…",
                ["step.service"] = "Ծառայության գրանցում…",
                ["step.start"] = "Գործարկում…",
                ["installed"] = "Պատրաստ է։ Suro ծրագիրը տեղադրված է և աշխատում է։\n\nԱդմինիստրատորի հաստատումից հետո կբացվի պատուհան, որտեղ պետք է լրացնել Ձեր անունը և ազգանունը։ Այս պատուհանը կարող եք փակել։",
                ["updated"] = "Պատրաստ է։ Suro ծրագիրը թարմացված է և աշխատում է։ Այս պատուհանը կարող եք փակել։",
                ["failed"] = "Տեղադրումը չհաջողվեց։ Դիմեք ադմինիստրատորին և ցույց տվեք այս հաղորդագրությունը։",
                ["close"] = "Փակել",
            },
            ["ru"] = new Dictionary<string, string>
            {
                ["title"] = "Установка программы Suro",
                ["working"] = "Программа Suro устанавливается. Пожалуйста, подождите и не выключайте компьютер.",
                ["step.stop"] = "Подготовка…",
                ["step.copy"] = "Копирование файлов…",
                ["step.service"] = "Регистрация службы…",
                ["step.start"] = "Запуск…",
                ["installed"] = "Готово. Программа Suro установлена и работает.\n\nПосле подтверждения администратором откроется окно, где нужно указать имя и фамилию. Это окно можно закрыть.",
                ["updated"] = "Готово. Программа Suro обновлена и работает. Это окно можно закрыть.",
                ["failed"] = "Установка не удалась. Обратитесь к администратору и покажите это сообщение.",
                ["close"] = "Закрыть",
            },
            ["en"] = new Dictionary<string, string>
            {
                ["title"] = "Suro setup",
                ["working"] = "Installing Suro. Please wait and do not turn off the computer.",
                ["step.stop"] = "Preparing…",
                ["step.copy"] = "Copying files…",
                ["step.service"] = "Registering the service…",
                ["step.start"] = "Starting…",
                ["installed"] = "Done. Suro is installed and running.\n\nAfter an administrator approves this computer, a window will ask for your first name and surname. You can close this window.",
                ["updated"] = "Done. Suro has been updated and is running. You can close this window.",
                ["failed"] = "Installation failed. Contact your administrator and show them this message.",
                ["close"] = "Close",
            },
        };

        public static string Get(string language, string key) =>
            (All.TryGetValue(language, out var texts) ? texts : All["hy"]).TryGetValue(key, out var text) ? text : key;
    }
}
