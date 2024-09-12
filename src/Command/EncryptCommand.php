<?php
namespace TurboLabIt\Encryptor\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use TurboLabIt\Encryptor\Encryptor;


#[AsCommand(name: 'encrypt', description: 'Encrypts a string')]
class EncryptCommand extends Command
{
    const CLI_ARG_INPUT = 'input';

    public function __construct(protected Encryptor $encryptor) { parent::__construct(); }

    protected function configure(): void
        { $this->addArgument(static::CLI_ARG_INPUT, InputArgument::REQUIRED, 'The string to encrypt'); }


    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->block('🔏 TLI text encryptor', null, 'fg=black;bg=cyan', ' ', true);

        $plainText = $input->getArgument(static::CLI_ARG_INPUT);

        $encryptedText = $this->encryptor->encrypt($plainText);
        $io->writeln("$plainText ➡ <info>$encryptedText</>");

        $io->block(
            '✔️  OK | ' . (new \DateTime())->format('Y-m-d H:i:s'),
            null, 'fg=black;bg=bright-green', ' ', true
        );

        return static::SUCCESS;
    }
}
