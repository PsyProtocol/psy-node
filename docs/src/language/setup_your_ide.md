# Psy LSP Developer Tutorial

Psy is a custom language with a dedicated Language Server Protocol (LSP) service, providing basic features such as `hover`, `goto definition`, `find references`, and `formatting`.

This document introduces how to use the Psy language server `psy-lsp-server` for a better development experience in **VSCode**, **Neovim**, and **RustRover**.

## 🛠️ Preparation

1. Clone repository:

```bash
  git clone https://github.com/PsyProtocol/psy-compiler.git
  cd psy-compiler
```

2. Compile `psy-lsp-server`：

```bash
  cd psy-lsp-server
  cargo build --release
```
> ⚠️ **Note**: Regardless of which IDE you are using, the `psy-lsp-server` binary is required for the language features to work properly.  
> Please make sure you have built it and **remember its path**.

## 💻 VSCode Usage Tutorial
Developer debugging mode (recommended for developers)
1. Start VSCode:
```bash
  cd psy-lsp-server/psy-lsp-vscode
  code .
```
2. Press F5 to enter plugin debugging mode. VSCode will start a new VSCode window and load the local plugin.
3. In the new window, open a Psy project containing Dargo.toml to enable plugin features, such as:
   * Mouse hover → Show type information
   * Right click → Goto Definition / Find References / Format


💡 Note:
In the file `psy-lsp-vscode/src/extension.ts`, the path to the `psy-lsp-server` binary is currently hardcoded:

```typescript
const serverExecutable = path.join(
    // Warning: this path is hardcoded and may not be portable across systems.
    context.extensionPath, '..', '..', 'target', 'release', 'psy-lsp-server'
);
```
This assumes you've built the LSP server in the `psy-compiler` directory. If you need to change the path (for example, to use a different build directory or binary location), please modify this line accordingly and then rebuild the extension by running:
```bash
  npm run build
```

## 🧑‍💻 Neovim Configuration for Psy

This guide shows how to configure Neovim for Psy development using the Language Server Protocol.

> ⚠️ **Prerequisites**: Ensure `psy-lsp-server` is installed and available in your PATH.

---

### 1️⃣ File Type Detection

Add this to your Neovim configuration to recognize `.psy` and `.qed` files:

```lua
-- File type detection for Psy files
vim.api.nvim_create_augroup("FiletypeConfig", { clear = true })

vim.api.nvim_create_autocmd({ "BufNewFile", "BufReadPost" }, {
    pattern = "*.psy",
    group = "FiletypeConfig",
    callback = function()
        vim.bo.filetype = "psy"
    end,
})

vim.api.nvim_create_autocmd({ "BufNewFile", "BufReadPost" }, {
    pattern = "*.qed",
    group = "FiletypeConfig",
    callback = function()
        vim.bo.filetype = "qed"
    end,
})
```

### 2️⃣ LSP Configuration

Configure the Psy language server:

```lua
-- Configure Psy LSP
vim.lsp.config('psy_lsp', {
    cmd = { "psy-lsp-server" },
    filetypes = { "psy", "qed" },
    root_markers = { "Dargo.toml" },
    settings = {},
})

-- Enable Psy LSP
vim.lsp.enable('psy_lsp')
```

### 3️⃣ Syntax Highlighting

Configure Tree-sitter to use Rust highlighting for Psy files:

```lua
-- Reuse Rust syntax highlighting for Psy files
vim.treesitter.language.register("rust", "psy")
vim.treesitter.language.register("rust", "qed")
```

### 4️⃣ LSP Key Mappings

Set up key bindings for LSP functionality:

```lua
-- LSP key mappings
vim.api.nvim_create_autocmd("LspAttach", {
    desc = "LSP actions",
    callback = function(event)
        local bufmap = function(mode, lhs, rhs)
            local opts = { buffer = true }
            vim.keymap.set(mode, lhs, rhs, opts)
        end

        -- Core LSP navigation
        bufmap("n", "gd", "<cmd>lua vim.lsp.buf.definition()<cr>")
        bufmap("n", "gr", "<cmd>lua vim.lsp.buf.references()<cr>")
        bufmap("n", "gi", "<cmd>lua vim.lsp.buf.implementation()<cr>")
        bufmap("n", "gy", "<cmd>lua vim.lsp.buf.type_definition()<cr>")

        -- Code actions and formatting
        bufmap("n", "<leader>f", "<cmd>lua vim.lsp.buf.format()<cr>")
        bufmap("n", "<leader>rn", "<cmd>lua vim.lsp.buf.rename()<cr>")
        bufmap("n", "<leader>ca", "<cmd>lua vim.lsp.buf.code_action()<cr>")
    end,
})
```

### 5️⃣ Comment Support

Configure comment strings for Psy files:

```lua
-- Comment configuration for Psy
vim.api.nvim_create_autocmd("FileType", {
    pattern = { "psy", "qed" },
    callback = function()
        vim.bo.commentstring = "//%s"
    end,
})
```

### 6️⃣ Complete Configuration Example

Here's a complete minimal configuration for Psy development:

```lua
-- File type detection
vim.api.nvim_create_augroup("FiletypeConfig", { clear = true })

local filetypes = {
    psy = "*.psy",
    qed = "*.qed",
}

for filetype, pattern in pairs(filetypes) do
    vim.api.nvim_create_autocmd({ "BufNewFile", "BufReadPost" }, {
        pattern = pattern,
        group = "FiletypeConfig",
        callback = function()
            vim.bo.filetype = filetype
        end,
    })
end

-- LSP configuration
vim.lsp.config('psy_lsp', {
    cmd = { "psy-lsp-server" },
    filetypes = { "psy", "qed" },
    root_markers = { "Dargo.toml" },
    settings = {},
})

vim.lsp.enable('psy_lsp')

-- Syntax highlighting
vim.treesitter.language.register("rust", "psy")
vim.treesitter.language.register("rust", "qed")

-- Comment support
vim.api.nvim_create_autocmd("FileType", {
    pattern = { "psy", "qed" },
    callback = function()
        vim.bo.commentstring = "//%s"
    end,
})

-- LSP key mappings
vim.api.nvim_create_autocmd("LspAttach", {
    desc = "LSP actions",
    callback = function(event)
        local bufmap = function(mode, lhs, rhs)
            local opts = { buffer = true }
            vim.keymap.set(mode, lhs, rhs, opts)
        end

        bufmap("n", "gd", "<cmd>lua vim.lsp.buf.definition()<cr>")
        bufmap("n", "gr", "<cmd>lua vim.lsp.buf.references()<cr>")
        bufmap("n", "<leader>f", "<cmd>lua vim.lsp.buf.format()<cr>")
        bufmap("n", "<leader>rn", "<cmd>lua vim.lsp.buf.rename()<cr>")
        bufmap("n", "<leader>ca", "<cmd>lua vim.lsp.buf.code_action()<cr>")
    end,
})
```

### 📚 Key Bindings Summary

| Key Binding | Function |
|-------------|----------|
| `gd` | Go to definition |
| `gr` | Find references |
| `gi` | Go to implementation |
| `gy` | Go to type definition |
| `<leader>f` | Format document |
| `<leader>rn` | Rename symbol |
| `<leader>ca` | Code actions |


## 🔧 Additional IDE Support

While VSCode and Neovim have official configuration guides, other IDEs may be supported through generic LSP clients. If you're using a different IDE that supports LSP, you can configure it to use `psy-lsp-server` as the language server for `.psy` files.

**General LSP Configuration:**
- **Server Command**: `psy-lsp-server`
- **File Extensions**: `*.psy`
- **Language ID**: `psy`
- **Root Pattern**: `Dargo.toml`

For specific IDE setup instructions, please refer to your IDE's LSP configuration documentation.

