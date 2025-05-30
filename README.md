<div align="center">
🛡️ **GoSonar**

**Binary Symbolic Execution for Go Binaries**  
*Detect and verify uncontrolled recursions with ease.*

![Docker Pulls](https://img.shields.io/docker/pulls/sakibanwar/gosonar?style=flat-square)
![License](https://img.shields.io/github/license/mdsakibanwar/gosonar?style=flat-square)
![Issues](https://img.shields.io/github/issues/mdsakibanwar/gosonar?style=flat-square)
![Stars](https://img.shields.io/github/stars/mdsakibanwar/gosonar?style=flat-square)
</div>

---

## 🚀 Overview

**GoSonar** is a tool for *binary symbolic execution* designed to detect **uncontrolled recursions** in Go binaries. This project is based on the research presented in the paper ["GoSonar: Detecting Logical Vulnerabilities in Memory Safe Languages Using Inductive Constraint Reasoning"](https://www.computer.org/csdl/proceedings-article/sp/2025/223600a043/21B7QweuVUs), published at IEEE S&P 2025.

GoSonar offers two primary modes for analysis:
- **Regular Mode**: Direct binary analysis.
- **Call Resolver Mode**: Source-assisted AST parsing to resolve indirect calls.

> 💬 *Recommended usage: Deploy via Docker container for optimal convenience.*

---

## 🐳 Quick Start

### 1. Pull & Run the Docker Image

```bash
docker run -it sakibanwar/gosonar bash
```

---

### 2. Project Structure

| Directory  | Purpose                         |
|------------|----------------------------------|
| `src/`     | Main source code.                |
| `bins/`    | Binaries + source for benchmarks and stdlib. |
| `db/`      | SQLite databases for analysis results. |
| `logs/`    | Logs of each execution run.       |

---

### 3. Running an Analysis

- Easiest way:  
  ```bash
  cd gosonar
  ./run.sh # runs benchmark
  ./run.sh <package> # runs package analysis assumes binary under go_stdlib in regular mode
  ./run.sh <package> call # runs package analysis assumes binary under go_stdlib in call resolver mode
  ```

- Or manually:  
  ```bash
  cd src/
  python3 main.py --worker-type <type> --binary <binary_path> --package <package_name> [other options]
  ```

---

### 4. Compiling Benchmarks

Each subdirectory under `bins/` has a `compile.sh` to build binaries:  
```bash
cd bins/benchmark/src
./compile.sh
```

---

## ⚙️ Modes of Operation

| Mode              | Description                                          |
|-------------------|------------------------------------------------------|
| Regular Mode      | Pure binary analysis.                                |
| Call Resolver Mode| Needs source code access. AST parsing for better call graph resolution. |

---

## 🗄️ Database and Logs

- **Databases** are saved inside `db/` folder (separate DB for each mode).
- **Logs** are saved under `logs/` and named:  
  ```
  <binary>_<worker>_<mode>_<timestamp>.log
  ```

---

## 🛠️ Command-Line Arguments

### Required
- `--worker-type` : Specifies the worker type (**mandatory**).

### At Least One Required
- `--package` : Target Go package.
- `--binary` : Path to binary file.

### Optional
- `--mode` : Running mode (`regular`, `callresolver`, etc.).  
- `--loglevel` : Logging level (`default: TRACE`).  
- `--target-func` : Analyze a specific function.  
- `--stop-addresses` : Addresses to stop execution at.  
- `--cycle-size` : Cycle size limit (`default: 5`).  
- `--db` : Target database.  
- `--recursion-limit` : Max recursion depth (`default: 3`).  
- `--db-id-start` : Starting database row (`default: 0`).  
- `--db-amount` : Number of rows to process (`default: 250`).  
- `--no-prune-callgraph` : Disable call graph pruning.  
- `--bypass-db` : Skip database operations.  
- `--timeout` : Analysis timeout (`default: 600s`).

---

## 📜 License

This project is licensed under the [GPL-3.0](LICENSE).

---

## ✨ Contributions

Pull requests are welcome!  
For major changes, please open an issue first to discuss what you would like to change.
