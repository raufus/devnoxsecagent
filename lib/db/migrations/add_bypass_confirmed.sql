-- Add bypass_confirmed column to findings table
ALTER TABLE findings 
ADD COLUMN bypass_confirmed BOOLEAN DEFAULT FALSE;
