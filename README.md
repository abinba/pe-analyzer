# pe_analyzer

## Introduction

The project focuses on preprocessing of PE (Portable Executable) files using PySpark and saving the results to database,
which then later can be used in detecting malicious files.

## Requirements

- Task
  - Take integer `N` as an input for the amount of files to preprocess
    - `N / 2` should be malicious files
    - `N / 2` should be clean files
    - `N` can be in order of millions
  - Other methods of providing task are expected, such as file with a list of file paths
- Database
  - Usage of structured database is preferred, but is subject to change in the future
- File storage
  - S3 bucket is provided with malicious and clean files in separate directories
- Spark
  - Spark should be used to:
    - Download files
    - Preprocess files
    - Store them in database
  - Spark job should skip already preprocessed files

## Metadata

Includes:

- file path
- file type (dll or exe)
- file size
- architecture
- number of imports
- number of exports

## Discussion and Trade-Offs

### Database Connecting Method

There are two optimal ways I found we can go with the saving and retrieving from the database:
- Using JDBC and saving the data at the end
- Using ORM and saving in partitions

Intuitively, saving with JDBC may seem faster as it could utilize the level of parallelism of PySpark and has a natural integration with dataframes.
However, I decided to benchmark each method.

| Method                           | Time taken for 100 files (sec) | Time taken for 1000 files (sec) |
|----------------------------------|--------------------------------|---------------------------------|
| Using JDBC and saving at the end | 15.32, 16.63                   | 150.58, 153.50                  |
| Using ORM and saving in partitions| 10.83, 11.88                   | 181.4, 177.51                   |                        |

**NOTE:** 2 tries were taken for each method

**NOTE:** was tested on machine with 16 cores

From the numbers, I may conclude that **using JDBC and saving at the end** is faster than using ORM and the difference would be more significant as the number of files increases.
However, **using ORM and saving in partitions** result _(arguably) in a more sustainable code_ and more importantly, data in partitions are saves as we go, meaning that in case of failure, the progress will be saved.

In case of using JDBC in the current project, I have not found a better way to retrieve not processed files than getting all the records and then filtering out processed files.
Alternatively, while using ORM, all records are not retrieved, which may result in a better performance in case of larger N input.

Again, I haven't found a way to use JDBC and save in partitions, but it doesn't mean that there isn't a way to do that.
But in scope of this project, those are the best options that I came up with.

### Preprocessing of files

Preprocessing was made using [pefile](https://pypi.org/project/pefile/) package.
Going through the documentation, I haven't found specific "tips or tricks" to make the preprocessing faster, and the only thing that
I found was using `fast_load`, which will not fully load all the contents.
However, I found that it may be only useful if we know in advance that the file is not `.dll` or `.exe`.

**Considerations for the improvement**: may be use `fast_load` first to identify if the file is dll or exe, and then do full load.

## Project Structure

```bash
├── pe_analyzer
│   ├── core
│   │   ├── __init__.py
│   │   ├── exceptions.py
│   │   ├── file_analyzer.py
│   │   ├── metadata_processor.py <- core functionality
│   │   ├── schema.py
│   │   └── utils.py
│   ├── db
│   │   ├── __init__.py
│   │   ├── alembic.ini
│   │   ├── models.py
│   │   ├── connector.py <- interface and implementation for different db connectors
│   │   ├── migrations
│   │   │   ├── env.py
│   │   │   ├── README
│   │   │   ├── script.py.mako
│   │   │   └── versions <-- Migrations lie here
│   ├── file_analysis
│   │   ├── __init__.py
│   │   ├── base.py <- interface for file analysis
│   │   ├── exceptions.py
│   │   └── pe_file_handler.py <- implementation with pe_file package
│   ├── file_storage
│   │   ├── __init__.py
│   │   ├── base.py <- interface for file storage
│   │   └── s3.py <- implementation for s3
│   ├── task_provider
│   │   ├── __init__.py
│   │   ├── base.py  <- interface for task provider
│   │   └── cmd_task.py  <- implementation with N as an input
│   ├── __init__.py
│   ├── __main__.py <- entrypoint for the processor
│   └── settings.py
├── poetry.lock
├── pyproject.toml
├── alembic.ini
├── docker-compose.yml
├── Dockerfile
├── spark.Dockerfile
├── scripts
│   └── entrypoint.sh  <- where N is specified
└── tests
    ├── __init__.py
    ├── conftest.py
    ├── core
    │   ├── __init__.py
    │   └── test_file_analyzer.py
    ├── file_analysis
    │   ├── __init__.py
    │   └── test_pe_file_handler.py
    ├── file_storage
    │   ├── __init__.py
    │   └── test_s3.py
    └── task_provider
        ├── __init__.py
        └── test_cmd_task.py
```

## Workflows

In the Github Actions, you can see two workflows:

1. `build.yml` <- code quality and tests coverage check
2. `run_analysis.yml` <- run the actual processing with docker-compose

## How to run the project

Using docker-compose:

```bash
docker compose up --build
```

## Settings

`pydantic-settings` was used for loading configuration and env variables.

You can set up database-related variables in `db.env`, for example:
```
DB_HOST=localhost
```

General env variables are set in `.env`, for example:
```
SPARK_URL=spark://spark:7077
```

## Migrations

Alembic was used for migrations.

To create a revision, please use

```bash
alembic revision --autogenerate -m "revision name"
```

To apply the migrations, use
```bash
alembic upgrade head
```


## Tests

To run tests with coverage statistics, please use:
```bash
poetry run pytest -vv --cov-report term-missing --cov-branch --cov=pe_analyzer ./tests
```
