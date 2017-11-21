local stdnse = require "stdnse" 
local smb = require "smb"
local smb2 = require "smb2"

description = [[Check for recently patched vulnerabilities]]

---
-- @usage nmap -p445 --script PATH_TO_NSE_SCRIPT --script-args winVulnDetection.csv=PATH_TO_CSV_FILE <target>
--
-- @outout
-- Host script results:
-- | winVulnDetection:
-- |   MS17-006: VULNERABLE
-- |   MS17-006 severity: Critical
-- |   CVE_line_2: CVE format incorrect
-- |_  MS17-008: No restart is needed
--
-- @args
--	winVulnDetection.csv=PATH_TO_CSV_FILE
---

categories = {"safe", "vuln", "external"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
author = "Lucie Gratuze and Carlos Polop Martin"

local function split_cve(str_cve)			--This function gets the needed information from each cve.
	local id, severity, restart, link, pubDate, titleSum
	id, severity, restart, link, pubDate, titleSum = str_cve:match("%s*'([^']*)'%s*,%s*'([^']*)'%s*,%s*'([^']*)'%s*,%s*'([^']*)'%s*,%s*'([^']*)'%s*,%s*'([^']*)'%s*")
	if id == nil then return nil end
	cve_array = {}
	cve_array["id"] = id:gsub("'", "")
	cve_array["severity"] = severity:gsub("'", "")
	cve_array["restart"] = restart:gsub("'", "")
	cve_array["link"] = link:gsub("'", "")
	cve_array["pubDate"] = pubDate:gsub("'", "")
	cve_array["titleSum"] = titleSum:gsub("'", "")
	return cve_array
end

local function get_pubDate(input_url)		-- This function connects to the url found in the .csv, retrieves the publication or last update date, and changes its format to a usable one.
	local http = require "http"
	local response = http.get_url(input_url)
	--stdnse.debug1("DEBUG HTTP response Body: %s",response.body)
	local html = response.body
	local pub_date = html:match("Published: ([^<]*)")
	--stdnse.debug1("DEBUG HTTP published: %s",pub_date)

	local day = pub_date:match("%d%d")
	local month = pub_date:match("^%a+")
	local year = pub_date:match("%d%d%d%d$")
	--stdnse.debug1("DEBUG HTTP day: %s",day)
	--stdnse.debug1("DEBUG HTTP month: %s",month)
	--stdnse.debug1("DEBUG HTTP year: %s",year)

	local month2
	if (month:find("Jan")) then month2 = '01'
	elseif (month:find("Feb")) then month2 = '02'
	elseif (month:find("Mar")) then month2 = '03'
	elseif (month:find("Apr")) then month2 = '04'
	elseif (month:find("May")) then month2 = '05'
	elseif (month:find("Jun")) then month2 = '06'
	elseif (month:find("Jul")) then month2 = '07'
	elseif (month:find("Aug")) then month2 = '08'
	elseif (month:find("Sep")) then month2 = '09'
	elseif (month:find("Oct")) then month2 = '10'
	elseif (month:find("Nov")) then month2 = '11'
	elseif (month:find("Dec")) then month2 = '12'
	end

	local globDate = year .. "-" .. month2 .. "-" .. day
	--stdnse.debug1("DEBUG HTTP pub_Date: %s",globDate)
	return globDate
end
	
local function file_exists(file)
	local f = io.open(file, "rb")
	if f then f:close() end
	return f ~= nil
  end
  

local function check_readFile(path)		--Checks that the file exists, and, if so, returns its content.
	if not file_exists(path) then return nil end
	lines = {}
	for line in io.lines(path) do 
	  lines[#lines + 1] = line
	end
	return lines
 end

local function  get_startDate_sbm(host)		--Connects to the smb port of a machine, and retrieves the date when the machine was started.
	local smbstate, status, overrides
	overrides = {}
	status, smbstate = smb.start(host)
	status = smb2.negotiate_v2(smbstate, overrides)
	if status then
		stdnse.debug1("SMB2: Date: %s (%s) Start date:%s (%s)", smbstate['date'], smbstate['time'], smbstate['start_date'], smbstate['start_time'])
		return smbstate['start_date']
	  else
		stdnse.debug1("Negotiation failed")
		return nil
	end
end

local function is_vuln(start_date, pub_date, output)		--Compares the publication date of the vulnerability and the start date of the machine.
	local year1, month1, day1 = start_date:match("(%d%d%d%d)-(%d%d)-(%d%d)")
	local year2, month2, day2 = pub_date:match("(%d%d%d%d)-(%d%d)-(%d%d)")

	if year1<year2 then return true 
	elseif year1>year2 then return false 
	elseif month1<month2 then return true 
	elseif month1>month2 then return false 
	elseif day1<day2 then return true 
	elseif day1>day2 then return false 

	else return false
	end
end

hostrule = function(host)		--Hostrule of our function: the smb port must be opened.
	return smb.get_port(host) ~= nil 
end

action = function(host, url)			--Main function: uses the previous ones to determine whether the machine is vulnerable or not.
	local output = stdnse.output_table()
	
	-- Check param
	local csv_path = stdnse.get_script_args(SCRIPT_NAME..".csv") or nil
	if (csv_path == nil) then
		output.error = "No csv file in args"
		--stdnse.debug1("DEBUG NOT ARG %s.csv",SCRIPT_NAME)
		return output
	end
	-- Check file exists
	local csv_content = check_readFile(csv_path)
	if (csv_content == nil) then
		output.error = "CSV file does not exist"
		--stdnse.debug1("DEBUG No exists csv %s",csv_path)
		return output
	end

	-- Get the start date of the machine
	local start_date = get_startDate_sbm(host)

	if (start_date == nil) then
		output.error = "SMB negociation failed"
		return output
	end

	for i, cve_content in ipairs(csv_content) do
		-- Check correct cve format
		local cve_array = split_cve(cve_content)
		if cve_array == nil then 
			output["CVE_line_"..i] = "CVE format incorrect"
		else
			-- Check if restart is needed
			if cve_array["restart"]:lower() ~= "yes" then
				output[cve_array["id"]] = "No restart is needed"
			
			else
				stdnse.debug1("DEBUG id: %s",cve_array["id"])
				stdnse.debug1("DEBUG severity: %s",cve_array["severity"])
				stdnse.debug1("DEBUG restart: %s",cve_array["restart"])
				stdnse.debug1("DEBUG link: %s",cve_array["link"])
				stdnse.debug1("DEBUG pubDate: %s",cve_array["pubDate"])
				--stdnse.debug1("DEBUG titleSum: %s",cve_array["titleSum"])
				
				-- Get the publication date in the web
				local pub_date = get_pubDate(cve_array["link"])
				
				local year2, month2, day2 = pub_date:match("(%d%d%d%d)-(%d%d)-(%d%d)")
				stdnse.debug1("DEBUG year2 = %s, month2 = %s, day2 = %s", year2, month2, day2)
				if (year2 == nil) then 
					output[cve_array["id"]] = "Incorrect date format in web page"
				else
					-- Finally, check if vulnerable	
					if (is_vuln(start_date, pub_date, output)) then
						output[cve_array["id"]] = "VULNERABLE"
						output[cve_array["id"].." severity"] = cve_array["severity"]
					else
						output[cve_array["id"]] = "Not Vulnerable"
					end
				end
			end
		end
	end
	return output
end
