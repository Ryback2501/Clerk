-- An application's name is how an administrator tells one client from another,
-- so it is claimed exclusively from here on.
--
-- Names were free-form before this, so a database being upgraded may hold two
-- that only differ by case or spacing. The index cannot be created over those,
-- and a failed migration stops Clerk from starting, so they are reconciled
-- first. Nothing a client depends on is touched: only the label changes.

-- Normalise what is stored: tabs and newlines become spaces, runs of spaces
-- collapse, and the ends are trimmed. Four passes collapse runs of up to 16
-- spaces, which is far beyond anything a name plausibly contains.
UPDATE applications
   SET name = trim(
           replace(replace(replace(replace(
             replace(replace(name, char(9), ' '), char(10), ' '),
           '  ', ' '), '  ', ' '), '  ', ' '), '  ', ' '));

-- Whatever still collides keeps the oldest row's name; the others are suffixed
-- with their id, which is unique, so the result cannot collide again.
UPDATE applications
   SET name = name || ' (' || id || ')'
 WHERE id IN (
     SELECT later.id
       FROM applications AS later
       JOIN applications AS earlier
         ON lower(earlier.name) = lower(later.name)
        AND earlier.id < later.id
 );

CREATE UNIQUE INDEX idx_applications_name_unique ON applications(lower(name));
