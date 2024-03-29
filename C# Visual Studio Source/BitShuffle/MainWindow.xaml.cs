﻿using System;
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
using System.Diagnostics;


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
        private System.TimeSpan startTime;
        private System.TimeSpan elaspedTime;
        private string elapseTime;
        

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

                Manipulate_Window_Objects();
                
            }
        }


        private void Window_Drop(object sender, DragEventArgs e)
        {
            string[] files = null;
            chkchangePass.IsChecked = false;

            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                files = e.Data.GetData(DataFormats.FileDrop, true) as string[];
            }

            if (files != null)
            {       //We dont want a folder    
                    if (!System.IO.Directory.Exists(files[0]))
                    {
                        encryptionFilePath = TxtFileLocation.Text = files[0];
                        fileExtension = System.IO.Path.GetExtension(files[0]);
                        fileName = System.IO.Path.GetFileNameWithoutExtension(files[0]);
                        directoryPath = System.IO.Path.GetDirectoryName(files[0]);

                        Manipulate_Window_Objects();
                    }     
            }
            else {
                MessageBox.Show("No files selected", "BitShuffle", MessageBoxButton.OK, MessageBoxImage.Exclamation);                       
            }
            
        }

        private async void BtnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            Stopwatch stopWatch;

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
                else if (string.IsNullOrEmpty(TxtKey.Password))
                {
                    MessageBox.Show("Passphrase field empty", "BitShuffle", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                }
                else if(showchkbox == true &&  string.IsNullOrEmpty(TxtOldKey.Password))
                {
                    MessageBox.Show("Existing Passphrase field empty", "BitShuffle", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                }
                else
                {
                    if (TxtKey.Password.Length >= 8)
                    {
                        //if the file selected is an encrypted file
                        if (validator.IsFileEncrypted(encryptionFilePath))
                        {
                            if (validator.ChkFileVersion(encryptionFilePath) == 6)
                            {  
                                //if the checkbox to change encrypted key 
                                if(showchkbox == true)
                                {
                                    stopWatch = new Stopwatch();
                                    stopWatch.Start();   

                                    LblStatus.Content = "Proceessing file...please wait";
                                    Task<bool> encryptionTask = new Task<bool>(() =>encryptor.ChangePassphrase(TxtOldKey.Password, TxtKey.Password, encryptionFilePath, directoryPath,
                                                      fileName, fileExtension));
                                    encryptionTask.Start();
                                    success = await encryptionTask;
                                    
                                    //elaspedTime = DateTime.Now.TimeOfDay - startTime;
                                    stopWatch.Stop();
                                    //elapseTime = stopWatch.Elapsed.ToString();
                                    
                                    TimeSpan ts = stopWatch.Elapsed;
                                    elapseTime = string.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                                    ts.Hours, ts.Minutes, ts.Seconds,
                                    ts.Milliseconds / 10);
                                    //elapseTime = ts.ToString();

                                }
                                else{

                                    stopWatch = new Stopwatch();
                                    stopWatch.Start();

                                    BtnEncrypt.IsEnabled = false;
                                    LblStatus.Content = "Proceessing file...please wait";
                                    Task<bool> decryptionTask = new Task<bool>(()=>encryptor.Decrypt(TxtKey.Password, encryptionFilePath, directoryPath,
                                                       fileName, fileExtension));
                                    decryptionTask.Start();
                                    success = await decryptionTask;
                                   
                                    stopWatch.Stop();
                                    TimeSpan ts = stopWatch.Elapsed;
                                    elapseTime = string.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                                    ts.Hours, ts.Minutes, ts.Seconds,
                                    ts.Milliseconds / 10);
                                }
                            }        
                        }
                        //non encrypted file selected. We must now encrypt the file
                        else
                        {
                            stopWatch = new Stopwatch();
                            stopWatch.Start();   
                            
                            BtnEncrypt.IsEnabled = false;
                            LblStatus.Content = "Proceessing file...please wait";
                            Task<bool> encryptionTask = new Task<bool>(() =>encryptor.Encrypt(TxtKey.Password, encryptionFilePath, directoryPath, fileName,
                                                  fileExtension));
                            encryptionTask.Start();
                            success = await encryptionTask;
                            stopWatch.Stop();

                            TimeSpan ts = stopWatch.Elapsed;
                            elapseTime = string.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                            ts.Hours, ts.Minutes, ts.Seconds,
                            ts.Milliseconds / 10);
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
                    LblStatus.Content = "Operation Successful in " + elapseTime;                  
                }
                else
                {
                    BtnEncrypt.IsEnabled = true;
                    LblStatus.Content = "Operation failed";
                }
            }
        }

        private void TxtFileLocation_TextChanged(object sender, TextChangedEventArgs e)
        {

        }
        
        private void Manipulate_Window_Objects() {

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
                TxtKeyConfirmation.Visibility = Visibility.Visible;
                LblConfirmPass.Visibility = Visibility.Visible;

                //we dont want to show the checkbox if the file is not an encrypted file
                chkchangePass.Visibility = Visibility.Hidden;
                showchkbox = false;
                lblExistingPass.Visibility = Visibility.Hidden;
                TxtOldKey.Visibility = Visibility.Hidden;
            }
        
        }
    }
}

