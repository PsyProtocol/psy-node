# Psy LSP Developer Tutorial

Psy is a custom language with a dedicated Language Server Protocol (LSP) service, providing basic features such as `hover`, `goto definition`, `find references`, and `formatting`.

This document introduces how to use the Psy language server `psy-lsp-server` for a better development experience in **VSCode**, **Neovim**, and **RustRover**.

## 🛠️ Preparation

1. Clone repository:

```bash
  git clone https://github.com/PsyProtocol/psy-v1.git
  cd psy-lang
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
If you need to change the path (for example, to use a different build directory or binary location), please modify this line accordingly and then rebuild the extension by running:
```bash
  npm run build
```

## 🧑‍💻 Neovim usage tutorial (based on Lazy.nvim)
This guide demonstrates how to set up the **Psy language server (`psy-lsp-server`)** in Neovim using the **lazy.nvim** plugin manager.

> ⚠️ **Note**: The `psy-lsp-server` binary must be compiled first and accessible in your system. Ensure the path to the binary is correct.

---
### 1️⃣ Plugin Installation

In your `init.lua`, make sure to install the necessary plugins:

```lua
require("lazy").setup({
  { "neovim/nvim-lspconfig" },             -- LSP support
  { "nvim-treesitter/nvim-treesitter", build = ":TSUpdate" }, -- syntax highlighting
  { "hrsh7th/nvim-cmp" },                  -- completion
  { "hrsh7th/cmp-nvim-lsp" },              -- LSP completion source
})
```
### 2️⃣ Psy LSP Setup via Lazy
```lua
local lspconfig = require("lspconfig")
local configs = require("lspconfig.configs")

-- Register custom LSP
if not configs.psy_lsp then
configs.psy_lsp = {
   default_config = {
      cmd = {"/full path/to/psy-lsp-server" }, -- ⚠️ Note to fill in the full path
      filetypes = {"psy"},
      root_dir = lspconfig.util.root_pattern("Dargo.toml"),
      settings = {},
   },
}
end

lspconfig.psy_lsp.setup({})

-- Let Neovim recognize the `.psy` file type
vim.filetype.add({
   extension = {
      psy = "psy",
   },
})
```


Instead of manually configuring LSP in init.lua, you can configure it via Lazy plugin opts.
Create a file like `~/.config/nvim/lua/plugins/lsp.lua` and write:
```lua
return {
  "neovim/nvim-lspconfig",
  opts = function(_, opts)
    -- Tell Neovim `.psy` files are of type `psy`
    vim.filetype.add({ extension = { psy = "psy" } })

    -- Reuse Rust Tree-sitter highlighting for `.psy` files
    vim.treesitter.language.register("rust", "psy")

    -- Load LSP config
    local lspconfig = require("lspconfig")
    local configs = require("lspconfig.configs")

    -- Register psy_lsp_server only once
    if not configs.psy_lsp_server then
      configs.psy_lsp_server = {
        default_config = {
          cmd = { "/full/path/to/psy-lsp-server" }, -- 🔧 Replace with your built binary
          filetypes = { "psy" },
          root_dir = lspconfig.util.root_pattern("Dargo.toml", ".psy"),
          settings = {},
        },
      }
    end

    -- Attach server config to Lazy's LSP handler
    opts.servers.psy_lsp_server = {}
    return opts
  end,
}
```

 ✅ Once you’ve saved this config, reopen Neovim and run :Lazy sync to apply it.

✅ Additional Notes
* 	`vim.filetype.add(...)` tells Neovim that `.psy` files should be handled as the psy filetype.
* 	`vim.treesitter.language.register("rust", "psy")` means `.psy`files will reuse Rust’s highlighting engine via Tree-sitter.
*	Make sure the `psy-lsp-server` binary is either in your PATH or referenced using the full path.

###  3️⃣ Navigation & Reference Lookup in Neovim
Once your psy-lsp-server is properly registered and running in Neovim, you can use the following built-in LSP keybindings to navigate your Psy code efficiently.
```lua
-- Place these in your init.lua or keymap config file if not already present
vim.keymap.set("n", "gd", vim.lsp.buf.definition, { noremap = true, desc = "Go to Definition" })
vim.keymap.set("n", "gr", vim.lsp.buf.references, { noremap = true, desc = "Find References" })
vim.keymap.set("n", "K", vim.lsp.buf.hover, { noremap = true, desc = "Hover Documentation" })
vim.keymap.set("n", "<leader>rn", vim.lsp.buf.rename, { noremap = true, desc = "Rename Symbol" })
vim.keymap.set("n", "<leader>f", vim.lsp.buf.format, { noremap = true, desc = "Format Document" })
```
📚 Common shortcut keys description

| Shortcuts | Functional description |
|---------------|--------------------------|
| `gd` | Jump to definition |
| `gr` | Find all references |
| `K` | Hover type information |
| `<leader>rn` | Rename symbol |
| `<leader>f` | Code formatting |
| `<C-o>` | Return to previous position (built-in) |


## ⚙️ RustRover usage tutorial (based on LSP4IJ plugin)

This tutorial assumes that you have already completed the configuration of Rust in RustRover.

We will use the LSP plugin `LSP Support (lsp4ij)` provided by RedHat to enable custom LSP support for `.psy` files, realizing functions such as jump, hover, reference lookup, code formatting, etc.

---

### 📦 Step 1: Install the LSP4IJ plugin

1. Open RustRover and click `RustRover > Settings` in the upper left corner (or use the shortcut `Cmd + ,`).
2. Go to `Plugins > Marketplace`.
3. Search for **lsp4ij** .
4. Click Install and restart the IDE after the installation is complete.
---


### ✅ Step 2: Create a Psy file type

1. Open `Settings` → `Editor` → `File Types`

2. Click **"+" Add** at the top to create a new File Type

3. Name: `Psy`

4. Description: `Psy language`

5. Configure highlighting (optional)
 fill in the following fields:

| Field name | Suggested value |
|------------------------------|--------------------------|
| **Line Comment** | `//` |
| **Block Comment Start** | `/*` |
| **Block Comment End** | `*/` |
| **Hex Prefix** | `0x` (optional) |
| **Number Postfixes** | `u32` (optional) |
| ✅ **Support Paired Braces** | ✔ Check |
| ✅ **Support Paired Brackets** | ✔ Check |
| ✅ **Support Paired Parentheses** | ✔ Check |
| ✅ **Support String Escapes** | ✔ Check |

Then click Save.

### 🧠 Step 3: Configure the Language Server of Psy language

Open `Settings > Languages && Frameworks > Language Servers`, we need to add a new configuration, click the plus sign ➕, there are three tabs in the new interface: **Server**, **Mapping** and **Configuration**.

#### ▶️ Server tab

Used to register a new LSP service.

- **Name**: Fill in `Psy language server`.
- **Environment Variables**: Leave it blank (optional, if you need to set `DARGO_STD_PATH`, you can fill it in here).
- **Command**: Fill in the path of your compiled LSP executable file, for example: `$HOME/bin/psy-lsp-server`

---

#### ▶️ Mapping tab

Used to map file types to language services.

- **Language**: Leave it blank.
- **FileType**: Click ➕, select `Psy` on the left, and enter `psy` on the right
  - Note: If there is no `Psy` option, please go back to step 2 and add the file type again.
- **Filename Patterns**: Click ➕, enter `*.psy` on the left, and enter `psy` on the right

📌 Note:

- The left side is the file type inside the IDE .
- The right side is the Language ID of the LSP Server, which needs to match your `textDocument.languageId`
---

#### ▶️ Configuration (optional)

You can set:

- **Server Trace Level**: Set to `Verbose` to view more debugging information

- **Client Trace Level**: Set to `Verbose` or `Info`
- To view LSP communication logs, it is recommended to open the `LSP Console` view
---


### ✅ Step 4: Verify if it works

1. Open a Psy project with `Dargo.toml`
2. Open the `.psy` file
3. You can try:
- `Hover` to view the type
- `Go to Definition`
- `Find References`
- `Format Document`


You can check the debug log in `View > Tool Windows > LSP Console` to confirm whether LSP is started correctly.

