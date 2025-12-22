/**
 * Seed script for Linux Loader & Linker Level Attacks course
 * Run with: npm run db:seed
 */

require('dotenv').config();
const db = require('../models');

const courseData = {
    title: 'Linux Loader & Linker Level Attacks',
    slug: 'linux-loader-linker-attacks',
    shortDescription: 'Deep dive into Linux internals - understand how programs load and execute to discover powerful attack vectors.',
    description: `
# Linux Loader & Linker Level Attacks

A comprehensive series on understanding the Linux program loading mechanism and how to abuse it for code execution.

## What You'll Learn

This course focuses on **understanding how Linux loads and executes programs** - knowledge that reveals powerful abuse vectors operating at levels most security tools don't monitor.

This is not about memory corruption or traditional exploitation. This is about understanding the **design and mechanisms** of program loading deeply enough to subvert them.

## The Philosophy

When you deeply understand how a system works, you discover ways to make it work for you - even in ways its designers never intended.

## Key Takeaways

- All attacks execute code **before main()** runs
- Traditional security tools often miss these techniques
- Understanding the loader gives you unprecedented control
    `,
    difficulty: 'advanced',
    estimatedHours: 20,
    tags: ['linux', 'elf', 'security', 'loader', 'linker', 'hooking', 'persistence'],
    prerequisites: 'Basic understanding of C programming, Linux command line, and ELF file format.',
    objectives: [
        'Understand Linux virtual memory layout and program loading',
        'Master ELF file structure and program headers',
        'Implement various loader-level attack techniques',
        'Create persistent hooks that survive reboots',
        'Detect and defend against loader-level attacks'
    ]
};

const chaptersData = [
    {
        title: 'Foundation & Trojanized Loader',
        orderIndex: 0,
        storyContext: 'Understanding the battlefield before we strike...',
        previouslySummary: null,
        learningObjectives: [
            'Understand Linux virtual memory layout',
            'Master ELF file structure and program headers',
            'Learn the complete process execution flow',
            'Implement a trojanized dynamic loader attack'
        ],
        estimatedMinutes: 60,
        content: `
# Foundation & The Trojanized Loader Attack

## Memory Layout

When a program runs, the operating system creates a virtual address space with these segments:

- **TEXT** (r-x): Program code
- **DATA** (rw-): Initialized globals, GOT
- **BSS** (rw-): Uninitialized globals
- **HEAP** (rw-): Dynamic memory (grows up)
- **STACK** (rw-): Local variables (grows down)

## ELF Program Headers

The kernel reads PT_INTERP to find the dynamic linker path. This is our attack vector!

## The Attack

By modifying the dynamic linker binary and patching PT_INTERP, we can execute code before ANY program runs.
        `,
        labs: [
            {
                title: 'Trojanized Loader POC',
                description: 'Implement a trojanized dynamic loader that executes code before any program',
                difficulty: 'hard',
                filesPath: '/home/spider/research/Trojanized_Loader_Attack',
                objectives: [
                    'Find a code cave in the loader binary',
                    'Inject shellcode that creates a marker file',
                    'Hook the entry point to execute our code first',
                    'Verify the attack works transparently'
                ],
                tools: ['gcc', 'objdump', 'xxd', 'readelf'],
                walkthrough: `
## Step 1: Analyze the Loader

First, find the entry point:
\`\`\`bash
readelf -h /lib64/ld-linux-x86-64.so.2 | grep Entry
\`\`\`

## Step 2: Find a Code Cave

Look for null bytes in the .text section padding.

## Step 3: Inject Payload

Write shellcode to create /tmp/PWNED_BY_LOADER

## Step 4: Hook Entry Point

Replace first instruction with JMP to our code.
                `,
                solution: `
See the POC at /home/spider/research/Trojanized_Loader_Attack/

Key files:
- trojanize_loader.py - Main injection script
- shellcode.asm - Payload assembly
                `
            }
        ]
    },
    {
        title: 'LD_PRELOAD Injection',
        orderIndex: 1,
        storyContext: 'The first weapon in our arsenal - environment-based function hijacking...',
        previouslySummary: 'We learned how the loader works and how to trojanize it.',
        learningObjectives: [
            'Understand LD_PRELOAD mechanism',
            'Implement function hooking via preloading',
            'Bypass SUID restrictions',
            'Create transparent function wrappers'
        ],
        estimatedMinutes: 45,
        labs: [
            {
                title: 'LD_PRELOAD Hook Implementation',
                description: 'Create a library that hooks libc functions via LD_PRELOAD',
                difficulty: 'medium',
                filesPath: '/home/spider/research/LD_PRELOAD',
                tools: ['gcc', 'ltrace', 'strace']
            }
        ]
    },
    {
        title: 'GOT/PLT Hijacking',
        orderIndex: 2,
        storyContext: 'Intercepting the messengers - redirecting function calls at runtime...',
        previouslySummary: 'We mastered LD_PRELOAD for function hooking.',
        learningObjectives: [
            'Understand lazy binding and PLT/GOT mechanism',
            'Implement GOT overwrite attacks',
            'Bypass Full RELRO protections'
        ],
        estimatedMinutes: 50,
        labs: [
            {
                title: 'GOT Overwrite Demo',
                description: 'Redirect function calls by modifying GOT entries',
                difficulty: 'medium',
                filesPath: '/home/spider/research/GOT_PLT_Hijacking',
                tools: ['gcc', 'gdb', 'objdump']
            }
        ]
    },
    {
        title: 'DT_RPATH/RUNPATH Exploitation',
        orderIndex: 3,
        storyContext: 'Poisoning the supply chain - controlling where libraries are loaded from...',
        previouslySummary: 'We learned to hijack function calls via GOT/PLT.',
        learningObjectives: [
            'Understand library search order',
            'Exploit DT_RPATH and DT_RUNPATH',
            'Create malicious library replacements'
        ],
        estimatedMinutes: 40,
        labs: [
            {
                title: 'RPATH Hijacking',
                description: 'Exploit library search paths to load malicious libraries',
                difficulty: 'medium',
                filesPath: '/home/spider/research/DT_RPATH_Exploitation',
                tools: ['gcc', 'patchelf', 'readelf']
            }
        ]
    },
    {
        title: 'DT_DEBUG Exploitation',
        orderIndex: 4,
        storyContext: "Reading the loader's diary - accessing internal linker structures...",
        previouslySummary: 'We exploited library search paths for persistent code injection.',
        learningObjectives: [
            'Understand r_debug structure',
            'Enumerate loaded libraries at runtime',
            'Access linker internals from running processes'
        ],
        estimatedMinutes: 45,
        labs: [
            {
                title: 'DT_DEBUG Traversal',
                description: 'Use DT_DEBUG to enumerate all loaded libraries',
                difficulty: 'medium',
                filesPath: '/home/spider/research/DT_DEBUG_Exploitation',
                tools: ['gcc', 'gdb']
            }
        ]
    },
    {
        title: '.init/.fini Array Injection',
        orderIndex: 5,
        storyContext: 'Planting seeds before dawn - constructor and destructor hooks...',
        previouslySummary: 'We accessed linker internals via DT_DEBUG.',
        learningObjectives: [
            'Understand .init_array and .fini_array',
            'Inject code that runs before/after main()',
            'Create persistent initialization hooks'
        ],
        estimatedMinutes: 40,
        labs: [
            {
                title: 'Init Array Injection',
                description: 'Add malicious constructors to .init_array',
                difficulty: 'medium',
                filesPath: '/home/spider/research/Init_Fini_Injection',
                tools: ['gcc', 'objcopy', 'readelf']
            }
        ]
    },
    {
        title: 'Symbol Versioning Attacks',
        orderIndex: 6,
        storyContext: 'Wearing a disguise - version-based symbol hijacking...',
        previouslySummary: 'We mastered constructor/destructor injection.',
        learningObjectives: [
            'Understand GNU symbol versioning',
            'Create versioned symbol hooks',
            'Bypass version checks'
        ],
        estimatedMinutes: 45,
        labs: [
            {
                title: 'Version Hijacking',
                description: 'Hijack specific symbol versions',
                difficulty: 'hard',
                filesPath: '/home/spider/research/Symbol_Versioning_Attacks',
                tools: ['gcc', 'readelf', 'objdump']
            }
        ]
    },
    {
        title: 'DT_NEEDED Injection',
        orderIndex: 7,
        storyContext: 'Permanent residency - adding ourselves to the dependency list...',
        previouslySummary: 'We exploited symbol versioning for targeted hooks.',
        learningObjectives: [
            'Understand DT_NEEDED entries',
            'Inject new library dependencies',
            'Create persistent library loading'
        ],
        estimatedMinutes: 40,
        labs: [
            {
                title: 'DT_NEEDED Injection with patchelf',
                description: 'Add malicious libraries to dependency list',
                difficulty: 'medium',
                filesPath: '/home/spider/research/DT_NEEDED_Injection',
                tools: ['patchelf', 'readelf', 'ldd']
            }
        ]
    },
    {
        title: 'LD_AUDIT Interface Abuse',
        orderIndex: 8,
        storyContext: 'The insider threat - abusing the auditing interface...',
        previouslySummary: 'We injected persistent dependencies with DT_NEEDED.',
        learningObjectives: [
            'Understand rtld-audit interface',
            'Implement audit library callbacks',
            'Hijack symbols via la_symbind64'
        ],
        estimatedMinutes: 50,
        labs: [
            {
                title: 'Audit Library Attack',
                description: 'Create malicious LD_AUDIT library',
                difficulty: 'hard',
                filesPath: '/home/spider/research/LD_AUDIT_Abuse',
                tools: ['gcc', 'ltrace']
            }
        ]
    },
    {
        title: 'IFUNC Resolver Hijacking',
        orderIndex: 9,
        storyContext: 'The ultimate first strike - earliest possible code execution...',
        previouslySummary: 'We mastered LD_AUDIT for symbol interception.',
        learningObjectives: [
            'Understand GNU IFUNC mechanism',
            'Execute code during symbol resolution',
            'Achieve earliest user-space code execution'
        ],
        estimatedMinutes: 45,
        labs: [
            {
                title: 'IFUNC Resolver Attack',
                description: 'Execute code during IFUNC resolution',
                difficulty: 'hard',
                filesPath: '/home/spider/research/IFUNC_Hijacking',
                tools: ['gcc', 'objdump', 'readelf']
            }
        ]
    }
];

async function seed() {
    try {
        await db.sequelize.authenticate();
        console.log('Database connected');

        // Sync database
        await db.sequelize.sync({ alter: true });

        // Check if course already exists
        const existing = await db.Course.findOne({ where: { slug: courseData.slug } });
        if (existing) {
            console.log('Course already exists. Updating...');
            await existing.update(courseData);
        }

        // Create or update course
        const [course] = await db.Course.upsert({
            ...courseData,
            isPublished: true
        }, {
            returning: true
        });

        console.log(`Course: ${course.title} (ID: ${course.id})`);

        // Create chapters and labs
        for (const chapterData of chaptersData) {
            const { labs, ...chapterFields } = chapterData;

            const [chapter] = await db.Chapter.upsert({
                ...chapterFields,
                courseId: course.id,
                slug: chapterFields.title.toLowerCase().replace(/[^a-z0-9]+/g, '-')
            }, {
                returning: true
            });

            console.log(`  Chapter ${chapter.orderIndex + 1}: ${chapter.title}`);

            // Create labs for this chapter
            if (labs) {
                for (let i = 0; i < labs.length; i++) {
                    const labData = labs[i];
                    await db.Lab.upsert({
                        ...labData,
                        chapterId: chapter.id,
                        orderIndex: i
                    });
                    console.log(`    Lab: ${labData.title}`);
                }
            }
        }

        console.log('\nSeeding complete!');
        console.log(`
╔═══════════════════════════════════════════════════════════════╗
║           LINUX ATTACKS COURSE SEEDED                         ║
╠═══════════════════════════════════════════════════════════════╣
║  Course: ${course.title.substring(0, 45).padEnd(45)}      ║
║  Chapters: ${chaptersData.length}                                                 ║
║  Labs: ${chaptersData.reduce((acc, ch) => acc + (ch.labs?.length || 0), 0)}                                                    ║
╚═══════════════════════════════════════════════════════════════╝
        `);

        process.exit(0);
    } catch (error) {
        console.error('Seeding error:', error);
        process.exit(1);
    }
}

seed();
