#include <Windows.h>

#include <stdio.h>

#include "args.h"

#include "common/str.h"

using namespace args;

argument_array::argument_array(int c, char* v[], enum switch_style style)
{
	this->is_ok					= false;
	this->number_of_arguments	= c;
	this->ElementArray			= new std::vector<PELEMENT>;

	// Get the name of the running process file location
	RunningProgramLocation		= new str_string(v[0]);

	if (c == 0) {
		this->is_ok = true;
		return;
	}

	if (style == switch_style::SWITCH_STYLE_SWITCHES) {
		for (int i = 1; i < c; i++) {	  
			// Sanity
			if (v[i][0] == '\0' || str::lenA(v[i]) > args::max_amount_per_elem) {
				this->clear_elements(*ElementArray);
				return;
			}

			PELEMENT current_element = (PELEMENT)mem::malloc(sizeof(ELEMENT));

			// Get the switch
			current_element->switch_data = v[i][1];

			// Get the switch data
			current_element->data = (LPSTR)mem::malloc(str::lenA(&v[++i][0]) + str::ASCII_CHAR);
			mem::copy(current_element->data, &v[i][0], str::lenA(&v[i][0]));

			this->ElementArray->push_back(current_element);
		}
	} else if (style == switch_style::SWITCH_STYLE_NO_SWITCHES) {
		//FIXME
		DebugBreak();
	} else {
		//FIXME
		DebugBreak();
	}



	return;
}

void argument_array::clear_elements(__inout std::vector<PELEMENT> elements)
{
	 if (elements.size() == 0) {
		return;
	 }

	 for (std::vector<PELEMENT>::iterator i = elements.begin(); 
		 i != elements.end(); 
		 i++) 
	 {
		if (this->switch_style == switch_style::SWITCH_STYLE_NO_SWITCHES) {
			mem::free((*i)->data);

			(*i)->data			= 0;
		} else if (this->switch_style == switch_style::SWITCH_STYLE_SWITCHES) {
			mem::free((*i)->data);

			(*i)->data			= 0;
			(*i)->switch_data	= 0;
		} else {
			//FIXME
			DebugBreak();
		}

	 }	

	 elements.clear();

	return;
}

const LPSTR argument_array::get_value_for_switch(__in const CHAR switch_value)
{
	if (this->ElementArray->size() == 0) {
		return NULL;
	}

	for (std::vector<PELEMENT>::const_iterator i = this->ElementArray->begin();
		i != ElementArray->end(); i++)
	{
		if (switch_value == (*i)->switch_data) {
			return (*i)->data;
		}
	}

	return NULL;
}