<?php
/**
 * This file is a part of the CIDRAM package.
 * Homepage: https://cidram.github.io/
 *
 * CIDRAM COPYRIGHT 2016 and beyond by Caleb Mazalevskis (Maikuolan).
 *
 * License: GNU/GPLv2
 * @see LICENSE.txt
 *
 * This file: PHPMailer event handlers (last modified: 2022.05.23).
 */

/**
 * Writes to the PHPMailer event log.
 *
 * @param string $Data What to write.
 * @return bool True on success; False on failure.
 */
$this->Events->addHandler('writeToPHPMailerEventLog', function (string $Data): bool {
    /** Guard. */
    if (
        $this->Configuration['phpmailer']['event_log'] === '' ||
        !($EventLog = $this->buildPath($this->Vault . $this->Configuration['phpmailer']['event_log']))
    ) {
        return false;
    }

    $Truncate = $this->readBytes($this->Configuration['general']['truncate']);
    $WriteMode = (!file_exists($EventLog) || $Truncate > 0 && filesize($EventLog) >= $Truncate) ? 'wb' : 'ab';
    $Handle = fopen($EventLog, $WriteMode);
    fwrite($Handle, $Data);
    fclose($Handle);
    if ($WriteMode === 'wb') {
        $this->logRotation($this->Configuration['phpmailer']['event_log']);
    }
    return true;
});

/**
 * Sends an email.
 *
 * @param string $Blank Intentionally left blank.
 * @param array $Data The data used to send the email.
 * @return bool True on success; False on failure.
 */
$this->Events->addHandler('sendEmail', function (string $Blank = '', array $Data): bool {
    /**
     * @var array $Recipients An array of recipients to send to.
     * @var string $Subject The subject line of the email.
     * @var string $Body The HTML content of the email.
     * @var string $AltBody The alternative plain-text content of the email.
     * @var array $Attachments An optional array of attachments.
     */
    [$Recipients, $Subject, $Body, $AltBody, $Attachments] = $ByReference;

    /** Prepare event logging. */
    $EventLogData = sprintf(
        '%s - %s - ',
        $this->Configuration['legal']['pseudonymise_ip_addresses'] ? $this->pseudonymiseIp($this->ipAddr) : $this->ipAddr,
        $this->FE['DateTime'] ?? $this->timeFormat($this->Now, $this->Configuration['general']['time_format'])
    );

    /** Operation success state. */
    $State = false;

    /** Check whether class exists to either load it and continue or fail the operation. */
    if (!class_exists('\PHPMailer\PHPMailer\PHPMailer')) {
        $EventLogData .= $this->L10N->getString('state_failed_missing') . "\n";
    } else {
        try {
            /** Create a new PHPMailer instance. */
            $Mail = new \PHPMailer\PHPMailer\PHPMailer();

            /** Tell PHPMailer to use SMTP. */
            $Mail->isSMTP();

            /** Tell PHPMailer to always use UTF-8. */
            $Mail->CharSet = 'utf-8';

            /** Disable debugging. */
            $Mail->SMTPDebug = 0;

            /** Skip authorisation process for some extreme problematic cases. */
            if ($this->Configuration['phpmailer']['skip_auth_process']) {
                $Mail->SMTPOptions = ['ssl' => [
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true
                ]];
            }

            /** Set mail server hostname. */
            $Mail->Host = $this->Configuration['phpmailer']['host'];

            /** Set the SMTP port. */
            $Mail->Port = $this->Configuration['phpmailer']['port'];

            /** Set the encryption system to use. */
            if (
                !empty($this->Configuration['phpmailer']['smtp_secure']) &&
                $this->Configuration['phpmailer']['smtp_secure'] !== '-'
            ) {
                $Mail->SMTPSecure = $this->Configuration['phpmailer']['smtp_secure'];
            }

            /** Set whether to use SMTP authentication. */
            $Mail->SMTPAuth = $this->Configuration['phpmailer']['smtp_auth'];

            /** Set the username to use for SMTP authentication. */
            $Mail->Username = $this->Configuration['phpmailer']['username'];

            /** Set the password to use for SMTP authentication. */
            $Mail->Password = $this->Configuration['phpmailer']['password'];

            /** Set the email sender address and name. */
            $Mail->setFrom(
                $this->Configuration['phpmailer']['set_from_address'],
                $this->Configuration['phpmailer']['set_from_name']
            );

            /** Set the optional "reply to" address and name. */
            if (
                !empty($this->Configuration['phpmailer']['add_reply_to_address']) &&
                !empty($this->Configuration['phpmailer']['add_reply_to_name'])
            ) {
                $Mail->addReplyTo(
                    $this->Configuration['phpmailer']['add_reply_to_address'],
                    $this->Configuration['phpmailer']['add_reply_to_name']
                );
            }

            /** Used by logging when send succeeds. */
            $SuccessDetails = '';

            /** Set the recipient address and name. */
            foreach ($Recipients as $Recipient) {
                if (empty($Recipient['Address']) || empty($Recipient['Name'])) {
                    continue;
                }
                $Mail->addAddress($Recipient['Address'], $Recipient['Name']);
                $SuccessDetails .= (($SuccessDetails) ? ', ' : '') . $Recipient['Name'] . ' <' . $Recipient['Address'] . '>';
            }

            /** Set the subject line of the email. */
            $Mail->Subject = $Subject;

            /** Tell PHPMailer that the email is written using HTML. */
            $Mail->isHTML = true;

            /** Set the HTML body of the email. */
            $Mail->Body = $Body;

            /** Set the alternative, plain-text body of the email. */
            $Mail->AltBody = $AltBody;

            /** Process attachments. */
            if (is_array($Attachments)) {
                foreach ($Attachments as $Attachment) {
                    $Mail->addAttachment($Attachment);
                }
            }

            /** Send it! */
            $State = $Mail->send();

            /** Log the results of the send attempt. */
            $EventLogData .= ($State ? sprintf(
                $this->L10N->getString('state_email_sent'),
                $SuccessDetails
            ) : $this->L10N->getString('response_error') . ' - ' . $Mail->ErrorInfo) . "\n";
        } catch (\Exception $e) {
            /** An exeption occurred. Log the information. */
            $EventLogData .= $this->L10N->getString('response_error') . ' - ' . $e->getMessage() . "\n";
        }
    }

    /** Write to the event log. */
    $this->Events->fireEvent('writeToPHPMailerEventLog', $EventLogData);

    /** Exit. */
    return $State;
}, true);
