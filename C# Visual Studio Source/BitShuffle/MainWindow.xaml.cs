using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Microsoft.Win32;
using Cryptography;


namespace BitShuffle
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public string fname;

        private OpenFileDialog fileDialogBox = new OpenFileDialog();
        private string encryptionFilePath;
        private DoEncry6 encryptor = new DoEncry6();
        private Validate validator = new Validate();
        private string directoryPath;
        private string fileName;
        private string fileExtension;
        private bool showchkbox = false;
 

        public MainWindow()
        {
            InitializeComponent();
            BtnEncrypt.Visibility = Visibility.Hidden;
        }


        private void CheckBox_Checked(object sender, RoutedEventArgs e)
        {
            showchkbox = true;
            lblExistingPass.Visibility = Visibility.Visible;
            TxtOldKey.Visibility = Visibility.Visible;
            TxtKeyConfirmation.Visibility = Visibility.Visible;
            LblConfirmPass.Visibility = Visibility.Visible;
            BtnEncrypt.Content = "Re encrypt";  
        }

        private void CheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            showchkbox = false;
            lblExistingPass.Visibility = Visibility.Hidden;
            TxtOldKey.Visibility = Visibility.Hidden;
            TxtKeyConfirmation.Visibility = Visibility.Hidden;
            LblConfirmPass.Visibility = Visibility.Hidden;
            BtnEncrypt.Content = "Decrypt"; 
        }
       
        private void BtnOpenFile_Click(object sender, RoutedEventArgs e)
        {
            LblStatus.Content = "";

            //if (fileDialogBox.DialogResult.HasValue && fileDialogBox.DialogResult.Value)
            if (fileDialogBox.ShowDialog() == DialogResult.GetValueOrDefault(true))
            {
                encryptionFilePath = TxtFileLocation.Text = fileDialogBox.FileName;
                fileExtension = System.IO.Path.GetExtension(fileDialogBox.FileName);
                fileName = System.IO.Path.GetFileNameWithoutExtension(fileDialogBox.FileName);
                directoryPath = System.IO.Path.GetDirectoryName(fileDialogBox.FileName);

                if (validator.IsFileEncrypted(encryptionFilePath))
                {
                    BtnEncrypt.Visibility = Visibility.Visible;
                    BtnEncrypt.Content = "Decrypt";
                    TxtKeyConfirmation.Visibility = Visibility.Hidden;
                    LblConfirmPass.Visibility = Visibility.Hidden;

                    //we want to show the checkbox if the file is an encrypted file
                    chkchangePass.Visibility = Visibility.Visible;
                }
                else
                {
                    BtnEncrypt.Visibility = Visibility.Visible;
                    BtnEncrypt.Content = "Encrypt";

                    //we want to show the confirmation passphrase label and text box
                    TxtKeyConfirmation.Visibility = Visibility.Visible ;
                    LblConfirmPass.Visibility = Visibility.Visible;

                    //we dont want to show the checkbox if the file is not an encrypted file
                    chkchangePass.Visibility = Visibility.Hidden;
                    showchkbox = false;
                    lblExistingPass.Visibility = Visibility.Hidden;
                    TxtOldKey.Visibility = Visibility.Hidden;
                }
                
            }
        }

        private async void BtnEncrypt_Click(object sender, RoutedEventArgs e)
        {        
            bool success = false;
            
            if (!fileDialogBox.CheckFileExists)
            {
                MessageBox.Show("File does not exist", "BitShuffle", MessageBoxButton.OK, MessageBoxImage.Exclamation);
            }
            else
            {
                if (!validator.IsFileEncrypted(encryptionFilePath) && !TxtKey.Password.Equals(TxtKeyConfirmation.Password) )
                {
                    MessageBox.Show("Passphrases do not match", "BitShuffle", MessageBoxButton.OK, MessageBoxImage.Exclamation);   
                }
                if (String.IsNullOrEmpty(TxtKey.Password))
                {
                    MessageBox.Show("Passphrase field empty", "BitShuffle", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                }
                if(showchkbox ==true &&  string.IsNullOrEmpty(TxtOldKey.Password))
                {
                    MessageBox.Show("Existing Passphrase field empty", "BitShuffle", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                }
                else
                {
                    if (TxtKey.Password.Length >= 8)
                    {
                        if (encryptionFilePath != null)
                        {
                            //if the file selected is an encrypted file
                            if (validator.IsFileEncrypted(encryptionFilePath))
                            {
                                if (validator.ChkFileVersion(encryptionFilePath) == 6)
                                {  
                                    //if the checkbox to change encrypted key 
                                    if(showchkbox == true)
                                    {
                                        LblStatus.Content = "Proceessing file...please wait";
                                        Task<bool> encryptionTask = new Task<bool>(() =>encryptor.ChangePassphrase(TxtOldKey.Password, TxtKey.Password, encryptionFilePath, directoryPath,
                                                          fileName, fileExtension));
                                        //MessageBox.Show("fdfdfd");
                                        encryptionTask.Start();
                                        success = await encryptionTask;
                                    }
                                    else{
                                        BtnEncrypt.IsEnabled = false;
                                        LblStatus.Content = "Proceessing file...please wait";
                                        Task<bool> decryptionTask = new Task<bool>(()=>encryptor.Decrypt(TxtKey.Password, encryptionFilePath, directoryPath,
                                                           fileName, fileExtension));
                                        decryptionTask.Start();
                                        success = await decryptionTask;
                                    }
                                }        
                            }
                            //non encrypted file selected. We must now encrypt the file
                            else
                            {
                                BtnEncrypt.IsEnabled = false;
                                LblStatus.Content = "Proceessing file...please wait";
                                Task<bool> encryptionTask = new Task<bool>(() =>encryptor.Encrypt(TxtKey.Password, encryptionFilePath, directoryPath, fileName,
                                                      fileExtension));
                                encryptionTask.Start();
                                success = await encryptionTask;
                            }
                        }

                        else
                        {
                            MessageBox.Show("No file selected", "BitShuffle", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                        }
                    }

                    else
                    {
                        MessageBox.Show("Passphrase needs to be at least 8 characters in length", "BitShuffle",MessageBoxButton.OK, MessageBoxImage.Exclamation);
                    }
                }

                if (success == true)
                {
                    BtnEncrypt.IsEnabled = true;
                    LblStatus.Content = "Operation Successful";                  
                }
                else
                {
                    BtnEncrypt.IsEnabled = true;
                    LblStatus.Content = "Operation failed";
                }
            }
        }

    }
}

