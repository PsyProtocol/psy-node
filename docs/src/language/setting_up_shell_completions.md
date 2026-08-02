# Setting up Shell Completions

Shell completions allow you to use the Tab key to autocomplete commands, options, and arguments when working with the
Psy CLI tools. This makes development faster and more convenient.

This guide will help you set up shell completions for the Dargo CLI.

## Zsh Completions

You can add the completions script to your Zsh completions directory:

```bash
# Create the completions directory if it doesn't exist
mkdir -p ~/.zsh/completions

# Generate and save the completion script
dargo complete zsh > ~/.zsh/completions/_dargo

# Add the directory to your fpath in ~/.zshrc if you haven't already
echo 'fpath=(~/.zsh/completions $fpath)' >> ~/.zshrc
echo 'autoload -U compinit && compinit' >> ~/.zshrc

# Reload your shell
source ~/.zshrc
```

## Bash Completions

You can add the completions script to your Bash environment in a few ways:

If you have bash-completion installed:

```bash
# Generate and save the completion script to the bash-completion directory
dargo complete bash > /usr/local/etc/bash_completion.d/dargo
```

Without bash-completion, you can add it to your profile:

```bash
# Create a completions directory if you don't have one
mkdir -p ~/.bash_completions

# Generate and save the completion script
dargo complete bash > ~/.bash_completions/dargo.bash

# Add the following line to your ~/.bash_profile or ~/.bashrc
echo 'source ~/.bash_completions/dargo.bash' >> ~/.bashrc

# Reload your shell
source ~/.bashrc
```

## Fish Completions

For Fish shell users, you can easily set up completions:

```bash
# Generate and save the completion script to the Fish completions directory
dargo complete fish > ~/.config/fish/completions/dargo.fish
```

No additional steps are needed as Fish automatically loads completions from this directory.

## Verifying Completions

To verify that completions are working correctly, type `dargo` followed by a space and press Tab. You should see a list
of available commands.

Try:

```bash
dargo <TAB>
```

You should see a list of commands like `new`, `build`, `compile`, etc.

## Troubleshooting

If completions aren't working:

1. Make sure you've restarted your terminal or sourced your `.zshrc` file
2. Check that the `dargo complete zsh` command works and produces output
3. Verify that the path to the completion script is correct
4. Ensure that Zsh completions are enabled in your shell configuration